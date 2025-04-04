package com.ts_24_25;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptionUtils {
    public static byte[] generateNonce() {
		//Tentar meter length como parametro e ajustar o tamanho do nonce
        byte[] nonce = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(nonce);

        return nonce;
    }

	public static byte[] rsaEncrypt(byte[] data, PublicKey publicKey) {
		byte[] encryptedBytes = null;

		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			encryptedBytes = cipher.doFinal(data);
		} catch (Exception e) {
			System.exit(255);
		}

		return encryptedBytes;
	}
	
	public static byte[] rsaDecrypt(byte[] encryptedData, PrivateKey privateKey) {
		byte[] decryptedBytes = null;

		try {
			Cipher d = Cipher.getInstance("RSA");
			d.init(Cipher.DECRYPT_MODE, privateKey);
			decryptedBytes = d.doFinal(encryptedData);
		} catch (Exception e) {
			System.exit(255);
		}
		
		return decryptedBytes;
	}

    //Keys tem de ser DH
    public static SecretKey createSessionKey(PrivateKey myPrivateKey, PublicKey otherPubKey) {
		SecretKey secretKey = null;

		try {
			KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
			keyAgreement.init(myPrivateKey);
	        keyAgreement.doPhase(otherPubKey, true);

	        byte[] sharedSecret = keyAgreement.generateSecret();
	        secretKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");
		} catch (Exception e) {
			System.exit(255);
		}

		return secretKey;
	}

    public static byte[] createHmac(SecretKey secretKey, byte[] message) {
		Mac hmacSha256;
		try {
			hmacSha256 = Mac.getInstance("HmacSHA256");
			hmacSha256.init(secretKey);
			byte[] hmacBytes = hmacSha256.doFinal(message);

			return hmacBytes;
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			System.exit(255);
		}

		return null;
	}

	public static boolean verifyHmac(SecretKey secretKey, byte[] message, byte[] hmac) {
        byte[] newHmac = createHmac(secretKey, message);
        return MessageDigest.isEqual(newHmac, hmac);
    }
	
	public static byte[] createHash(byte[] message) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");

			return digest.digest(message);
		} catch (NoSuchAlgorithmException e) {
			System.exit(255);
		}

		return null;
	}
	
	public static byte[] sign(byte[] hash, PrivateKey privateKey) {
        Signature signature;

		try {
			signature = Signature.getInstance("SHA256withRSA");
			signature.initSign(privateKey);
	        signature.update(hash);

	        return signature.sign();
		} catch (Exception e) {
			System.exit(255);
		}

		return null;
    }
	
	public static boolean verifySignature(byte[] hash, byte[] signature, PublicKey publicKey) {
        Signature verifier;

		try {
			verifier = Signature.getInstance("SHA256withRSA");
			verifier.initVerify(publicKey);
	        verifier.update(hash);

	        return verifier.verify(signature);
		} catch (Exception e) {
			System.exit(255);
		}

		return false; 
    }

	// Encrypt method: Takes a plaintext string and a secret key, returns an encrypted byte array
    public static byte[] encrypt(byte[] plaintext, SecretKey secretKey) throws Exception {
        // Generate a random 16-byte Initialization Vector (IV)
        byte[] iv = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Initialize Cipher in encryption mode with AES/CBC/PKCS5Padding
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        // Encrypt the plaintext
        byte[] encryptedText = cipher.doFinal(plaintext);

        // Concatenate IV with the encrypted text
        byte[] ivAndEncryptedText = new byte[iv.length + encryptedText.length];
        System.arraycopy(iv, 0, ivAndEncryptedText, 0, iv.length);
        System.arraycopy(encryptedText, 0, ivAndEncryptedText, iv.length, encryptedText.length);

        return ivAndEncryptedText;
    }

	// Decrypt method: Takes an encrypted byte array and a secret key, returns the decrypted plaintext
    public static byte[] decrypt(byte[] ivAndEncryptedText, SecretKey secretKey) throws Exception {
        // Extract IV from the first 16 bytes
        byte[] iv = new byte[16];
        System.arraycopy(ivAndEncryptedText, 0, iv, 0, iv.length);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Extract the encrypted text
        byte[] encryptedText = new byte[ivAndEncryptedText.length - iv.length];
        System.arraycopy(ivAndEncryptedText, iv.length, encryptedText, 0, encryptedText.length);

        // Initialize Cipher in decryption mode with AES/CBC/PKCS5Padding
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        // Decrypt the encrypted text
        byte[] decryptedText = cipher.doFinal(encryptedText);

        return decryptedText;
    }

	public static byte[] encryptAndHmac(byte[] plaintextWSequenceNumber, SecretKey secretKey) {
		// Encrypt the plaintext with the secret key
		byte[] cypherText = null;

		try {
			cypherText = encrypt(plaintextWSequenceNumber, secretKey);
		} catch (Exception e) {
			System.exit(255);
		}

		// Create the HMAC of the cypherText
		byte[] hmac = createHmac(secretKey, cypherText);

		// Concatenate the cypherText with the HMAC
		byte[] cypherTextAndHmac = new byte[cypherText.length + hmac.length];
		System.arraycopy(cypherText, 0, cypherTextAndHmac, 0, cypherText.length);
		System.arraycopy(hmac, 0, cypherTextAndHmac, cypherText.length, hmac.length);		

		return cypherTextAndHmac;
	}

	public static byte[] decryptAndVerifyHmac(byte[] cypherTextAndHmac, SecretKey secretKey) {

		// Extract the cypherText from the cypherTextAndHmac
		byte[] cypherText = new byte[cypherTextAndHmac.length - 32];
		System.arraycopy(cypherTextAndHmac, 0, cypherText, 0, cypherText.length);

		// Extract the HMAC from the cypherTextAndHmac
		byte[] hmac = new byte[32];
		System.arraycopy(cypherTextAndHmac, cypherText.length, hmac, 0, hmac.length);

		// Verify the HMAC
		if (!verifyHmac(secretKey, cypherText, hmac)) {
			System.exit(255);
		}

		// Decrypt the cypherText
		byte[] plaintext = null;
		try {
			plaintext = decrypt(cypherText, secretKey);
		} catch (Exception e) {
			System.exit(255);
		}		

		return plaintext;
	}

    //Keys tem de ser DH
    public static SecretKey createSessionKey(PrivateKey ownPrivateKey, byte[] othersPublicKey) {
		SecretKey secretKey = null;

		try {
			KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
			keyAgreement.init(ownPrivateKey);

	        KeyFactory keyFactory = KeyFactory.getInstance("DH");
	        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(othersPublicKey);
	        PublicKey otherPubKey = keyFactory.generatePublic(x509KeySpec);

	        keyAgreement.doPhase(otherPubKey, true);
	        byte[] sharedSecret = keyAgreement.generateSecret();
			
	        secretKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");
			
		} catch (Exception e) {
			System.exit(255);
		}

		return secretKey;
	}

    public static byte[] Hmac(SecretKey secretKey, byte[] message) {
		Mac hmacSha256;
		try {
			hmacSha256 = Mac.getInstance("HmacSHA256");
			hmacSha256.init(secretKey);
			byte[] hmacBytes = hmacSha256.doFinal(message);

			return hmacBytes;
		} catch (Exception e) {
			System.exit(255);
		}

		return null;
	}
	
	public static byte[] hash(byte[] message) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");

			return digest.digest(message);
		} catch (Exception e) {
			System.exit(255);
		}

		return null;
	}

}