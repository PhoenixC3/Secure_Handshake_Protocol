package com.ts_24_25;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

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
