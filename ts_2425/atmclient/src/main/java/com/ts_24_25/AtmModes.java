package com.ts_24_25;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import javax.crypto.SecretKey;

public class AtmModes {

    public static void createAccount(ClientRequestMsg requestMessage, String account, ObjectInputStream in, ObjectOutputStream out, PublicKey authBank, PrivateKey privateKey) {
        Path path = Paths.get(requestMessage.getCardFile());
		if (Files.exists(path)) {
			System.exit(255);
		}

        //Criar chaves do cliente
        PublicKey publicKey = null;

        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);

            KeyPair kp = kpg.generateKeyPair();
            privateKey = kp.getPrivate();
            publicKey = kp.getPublic();
        } catch (NoSuchAlgorithmException e) {
            System.exit(255);
        }

        //Enviar chave publica para o banco
        byte[] publicKeyBytes = publicKey.getEncoded();
        try {
            out.writeObject(publicKeyBytes);
        } catch (Exception e) {
            System.exit(255);
        }

        //Criar card file

        //-------------------Autenticacao mutua (FALTA sequence numbers)

        //Troca de nonce
        clientAuthenticationChallenge(in, out, authBank, privateKey);

        //Diffie Hellman
        SecretKey secretKey = clientDH(in, out, authBank, privateKey);

        //-------------------Fim de autenticacao mutua

        //Depois vai ser encriptada com a chave secreta DH e enviada
    }

    private static boolean clientAuthenticationChallenge(ObjectInputStream inFromServer, ObjectOutputStream outToServer, PublicKey bankPublicKey, PrivateKey privateKey) {
		try {
			//Receiving nonce from bank
			byte[] nonceEncrypted = (byte[]) inFromServer.readObject();
			byte[] nonceDecrypted = EncryptionUtils.rsaDecrypt(nonceEncrypted, privateKey); 
			
			byte[] encryptedBytes = EncryptionUtils.rsaEncrypt(nonceDecrypted, bankPublicKey);
			outToServer.writeObject(encryptedBytes);
			
			//Generate nonce and send it to bank - bank has to authenticate
			byte[] nonce = EncryptionUtils.generateNonce();
			byte[] encryptedNonceMessage = EncryptionUtils.rsaEncrypt(nonce, bankPublicKey);
			outToServer.writeObject(encryptedNonceMessage);
			
			//Receive nonce back from the bank
			byte[] receivedNonceBytes = (byte[]) inFromServer.readObject();
			byte[] receivedNonceMessage = EncryptionUtils.rsaDecrypt(receivedNonceBytes, privateKey);
			
			if (!Arrays.equals(nonce, receivedNonceMessage)) {
				return false;
			}
		 } catch(SocketTimeoutException e) {
			System.out.println("protocol_error");
			System.exit(63);
		 } catch(Exception e) {
			return false; 
		 } 
			
		return true;
	}

	private static SecretKey clientDH(ObjectInputStream in, ObjectOutputStream out, PublicKey authBank, PrivateKey privateKey) {
		SecretKey secretKey = null;
		try {
			//Start of Diffie Hellman
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
	        keyPairGenerator.initialize(2048);
	        KeyPair clientKeyPair = keyPairGenerator.generateKeyPair();
	        
	        byte[] clientPublicKey = clientKeyPair.getPublic().getEncoded();
	        
	        //Client receives publicKey DH of server
			byte[] bankDHPublicKey = (byte[]) in.readObject(); //DH public key of the bank
			byte[] dhPubKeyHash = EncryptionUtils.createHash(bankDHPublicKey);
			
			//Receive signed hash of the server's DH public key
			byte[] bankDHPublicKeySignedHash = (byte[]) in.readObject();
			
			//Check if it matches the signature from the bank
			if (!EncryptionUtils.verifySignature(dhPubKeyHash, bankDHPublicKeySignedHash, authBank)) return null;
			
			//Client sends its DH publicKey to server
	        out.writeObject(clientPublicKey);
	        
	        //Send a signed hash of the public key to confirm it is correct
	        byte[] dhPublicKeyHash = EncryptionUtils.createHash(clientPublicKey);
	        byte[] dhPublicKeyHashSigned = EncryptionUtils.sign(dhPublicKeyHash, privateKey);
	        out.writeObject(dhPublicKeyHashSigned);
	        
	        secretKey = EncryptionUtils.createSessionKey(clientKeyPair.getPrivate(), bankDHPublicKey);
		} catch(SocketTimeoutException e) {
			System.out.println("protocol_error");
			System.exit(63);
	    } catch (Exception e) {
			System.exit(255);
		}

		return secretKey;
	}

}
