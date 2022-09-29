package com.brillio.tokenization.awsS3;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.SdkClientException;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.S3ObjectInputStream;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;

public class GetObject {

//	// Tokenization
	private static String tokenKey = "JaveedSrinivasan";
	private static ArrayList<String> cardNumber = new ArrayList<String>();
	private static ArrayList<String> cardHolderName = new ArrayList<String>();
	private static ArrayList<String> cardHolderEmail = new ArrayList<String>();
	private static ArrayList<String> cardHolderPhoneNumber = new ArrayList<String>();
	private static ArrayList<String> tokenizedCards = new ArrayList<String>();
	private static SecretKey secretKey;
	
	// Tokenization of a card
		private static void tokenizeCard(InputStream input) throws NoSuchAlgorithmException, InvalidKeyException,
				NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
			
			// Calling getCardNumber function to collect the card numbers
			getCardNumber(input);

			// Call generateKey function to Generating a SecretKey
			secretKey = generateKey();

			// Calling encrypt function to Tokenize the cards
			encrypt(secretKey, cardNumber);

		}
		
		// Getting the cardNumber and Storing in cardNumber ArrayList
		private static void getCardNumber(InputStream input) {
			long readLines = 0;
			BufferedReader reader = new BufferedReader(new InputStreamReader(input));

			try {
				String line = null;
				// Reading Line till we get null
				while ((line = reader.readLine()) != null) {
					if (readLines > 0) {
						String[] rowData = {};
						rowData = line.split(",");
//						System.out.println("RowData :" + rowData[2]);
//						System.out.println(line);
//						System.out.println("Line Number :" + readLines);
						cardNumber.add(rowData[2]);
						cardHolderName.add(rowData[1]);
						cardHolderEmail.add(rowData[5]);
						cardHolderPhoneNumber.add(rowData[6]);
					}
					readLines++;
				}
			} catch (Exception e) {
				// TODO: handle exception
				System.out.println("Error occured in lambda: " + e.getMessage());
			}

		}
		
		// Generate Key to encrypt
		private static SecretKey generateKey() throws NoSuchAlgorithmException {
			byte[] secretKeyBytes1 = tokenKey.getBytes();
			SecretKey secretKey = new SecretKeySpec(secretKeyBytes1, "AES");
			System.out.println(secretKey.getEncoded());
			return secretKey;
		}
		
		
		// Encryption of a cardNumber
		private static void encrypt(SecretKey secretKey, ArrayList<String> cardNumbers)
				throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
				InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");

			Cipher encryptionCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			byte[] InitVectorBytes = keyGenerator.generateKey().getEncoded();
			IvParameterSpec parameterSpec = new IvParameterSpec(InitVectorBytes);
			encryptionCipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

			// Adding encrypted data to tokenizedCards ArrayList
			for (int i = 0; i < cardNumbers.size(); i++) {
				byte[] encryptedMessageBytes = encryptionCipher.doFinal(cardNumbers.get(i).getBytes());
				String encryptedMessage = Base64.getEncoder().encodeToString(encryptedMessageBytes);
				tokenizedCards.add(encryptedMessage);
				System.out.println("Encrypted Message :"+encryptedMessage);
			}

//			//Decrypt the encrypted message
//	        Cipher decryptionCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//	        decryptionCipher.init(Cipher.DECRYPT_MODE,secretKey,parameterSpec);
//	        byte[] encryptedMessageBytes = encryptionCipher.doFinal(cardNumbers.get(0).getBytes());
//	        byte[] decryptedMessageBytes =
//	        decryptionCipher.doFinal(encryptedMessageBytes);
//	        String decryptedMessage = new String(decryptedMessageBytes);
//	        System.out.println("decrypted message ="+decryptedMessage);

		}
		
		// To Display the CradDetails
		private static void displayTokenizedCardNumber() {
			for (int i = 0; i < tokenizedCards.size(); i++) {
				System.out.println("Tokenized Cards " + i + " :" + tokenizedCards.get(i));
			}
		}
		

	public static void main(String[] ars)
			throws DecoderException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException {

		Regions clientRegion = Regions.AP_SOUTH_1;
		String bucketName = "stormbreakers";
		String key = "Tockanization_DB-3.csv";

		S3Object fullObject = null, objectPortion = null, headerOverrideObject = null;
		try {
			AmazonS3 s3Client = AmazonS3ClientBuilder.standard().withRegion(clientRegion)
					.withCredentials(DefaultAWSCredentialsProviderChain.getInstance()).build();

			// Get an object
			System.out.println("Downloading an object");
			S3Object s3Object = s3Client.getObject(bucketName, key);
			S3ObjectInputStream inputStream = s3Object.getObjectContent();
			
			// Calling the Tokenization Function
			tokenizeCard(inputStream);

		} catch (AmazonServiceException e) {
			// The call was transmitted successfully, but Amazon S3 couldn't process
			// it, so it returned an error response.
			e.printStackTrace();
		} catch (SdkClientException e) {
			// Amazon S3 couldn't be contacted for a response, or the client
			// couldn't parse the response from Amazon S3.
			e.printStackTrace();
		} finally {
			// To ensure that the network connection doesn't remain open, close any open
			// input streams.
			if (fullObject != null) {
				fullObject.close();
			}
			if (objectPortion != null) {
				objectPortion.close();
			}
			if (headerOverrideObject != null) {
				headerOverrideObject.close();
			}
		}
		// Display the CardNumber
//		displayTokenizedCardNumber();

	}

}
