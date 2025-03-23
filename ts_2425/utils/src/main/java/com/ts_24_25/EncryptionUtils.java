package com.ts_24_25;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
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
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			System.exit(255);
		}

		return null;
	}
	
	public static byte[] hash(byte[] message) {
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
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
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
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			System.exit(255);
		}

		return false; 
    }
}
