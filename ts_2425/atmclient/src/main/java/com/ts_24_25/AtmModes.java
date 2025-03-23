package com.ts_24_25;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
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

	private int messageCounter = 0;

    public void createAccount(ClientRequestMsg requestMessage, String account, ObjectInputStream in, ObjectOutputStream out, PublicKey authBank, PrivateKey privateKey) {
		// Verificar balance
		if (requestMessage.getAmount() < 10.00) {
			System.exit(255);
		}

		//Verificar se conta ja existe
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

			//Criar card file
			try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(requestMessage.getCardFile()))) {
				oos.writeObject(kp);
			} catch (IOException e) {
				File cfile = new File(requestMessage.getCardFile());

				if (cfile.exists()) { 
					cfile.delete();
				}

				System.exit(255);
			} 
        } catch (NoSuchAlgorithmException e) {
			File cfile = new File(requestMessage.getCardFile());

			if (cfile.exists()) { 
				cfile.delete();
			}

            System.exit(255);
        }

        try {
			//Enviar o request para o banco
			MsgSequence messageToSend = new MsgSequence(CommUtils.serializeBytes(requestMessage.getCmdType()), messageCounter);
			byte[] encryptedBytes = EncryptionUtils.rsaEncrypt(CommUtils.serializeBytes(messageToSend), authBank);
			out.writeObject(encryptedBytes);
			messageCounter++;

			//Enviar chave publica para o banco
			messageToSend = new MsgSequence(CommUtils.serializeBytes(publicKey), messageCounter);

			out.writeObject(messageToSend);
			messageCounter++;
        } catch (Exception e) {
            System.exit(255);
        }

        //-------------------Autenticacao mutua

        //Troca de nonce
        if (!clientNonceExchange(in, out, authBank, privateKey)) {
			File cfile = new File(requestMessage.getCardFile());

			if (cfile.exists()) { 
				cfile.delete();
			}

			System.exit(255);
		}

        //Diffie Hellman
        SecretKey secretKey = clientDH(in, out, authBank, privateKey);
		if (secretKey == null) {
			File cfile = new File(requestMessage.getCardFile());

			if (cfile.exists()) { 
				cfile.delete();
			}

			System.exit(255);
		}

        //-------------------Fim de autenticacao mutua

        //Depois vai ser encriptada com a chave secreta DH e enviada
    }

	// public static void deposit(ClientRequestMsg requestMessage, String account, ObjectInputStream in, ObjectOutputStream out, PublicKey authBank, PrivateKey privateKey) {
	// 	// Ensure deposit amount is valid
	// 	double amount = requestMessage.getAmount();
	// 	if (amount <= 0.00) {
	// 		System.exit(255);
	// 	}
		
	// 	// Ensure the card file exists and is valid
	// 	Path path = Paths.get(requestMessage.getCardFile());
	// 	if (!Files.exists(path)) {
	// 		System.exit(255);
	// 	}
		
	// 	// Perform mutual authentication with the bank
	// 	if (!clientNonceExchange(in, out, authBank, privateKey)) {
	// 		System.exit(255);
	// 	}
		
	// 	// Establish a secure session key using Diffie-Hellman
	// 	SecretKey secretKey = clientDH(in, out, authBank, privateKey);
	// 	if (secretKey == null) {
	// 		System.exit(255);
	// 	}
		
	// 	try {
	// 		// Create a deposit request message
	// 		DepositRequest depositRequest = new DepositRequest(account, amount);
	// 		byte[] encryptedRequest = EncryptionUtils.encryptObject(depositRequest, secretKey);
			
	// 		// Send encrypted deposit request to the bank
	// 		out.writeObject(encryptedRequest);
	// 		out.flush();
			
	// 		// Receive response from the bank
	// 		byte[] encryptedResponse = (byte[]) in.readObject();
	// 		DepositResponse depositResponse = (DepositResponse) EncryptionUtils.decryptObject(encryptedResponse, secretKey);
			
	// 		// Validate response
	// 		if (!depositResponse.getAccount().equals(account) || depositResponse.getDeposit() != amount) {
	// 			System.exit(255);
	// 		}
			
	// 		// Print the JSON output
	// 		System.out.println("{" + "\"account\":\"" + depositResponse.getAccount() + "\", " + "\"deposit\":" + depositResponse.getDeposit() + "}");
	// 	} catch (Exception e) {
	// 		System.exit(255);
	// 	}
	// }

	// public static void withdraw(ClientRequestMsg requestMessage, String account, ObjectInputStream in, ObjectOutputStream out, PublicKey authBank, PrivateKey privateKey) {
	// }

	// public static void balance(ClientRequestMsg requestMessage, String account, ObjectInputStream in, ObjectOutputStream out, PublicKey authBank, PrivateKey privateKey) {
	// }

    private boolean clientNonceExchange(ObjectInputStream in, ObjectOutputStream out, PublicKey authBank, PrivateKey privateKey) {
		try {
			//---- CLIENT AUTH

			// Receber nonce do banco e decrypt
			byte[] nonceEncrypted = (byte[]) in.readObject();
			byte[] nonceDecrypted = EncryptionUtils.rsaDecrypt(nonceEncrypted, privateKey);
			MsgSequence nonceDecryptedMsg = (MsgSequence) CommUtils.deserializeBytes(nonceDecrypted);

			if (nonceDecryptedMsg.getSeqNumber() != messageCounter) {
				return false;
			}

			messageCounter++;
			
			// Encrypt e reenviar para o banco
			MsgSequence nonceToSend = new MsgSequence(nonceDecryptedMsg.getMsg(), messageCounter);
			byte[] encryptedBytes = EncryptionUtils.rsaEncrypt(CommUtils.serializeBytes(nonceToSend), authBank);

			out.writeObject(encryptedBytes);
			messageCounter++;
			
			//Resposta do banco
			MsgSequence challengeResult = (MsgSequence) in.readObject();
			String result = (String) CommUtils.deserializeBytes(challengeResult.getMsg());
			
			if (challengeResult.getSeqNumber() != messageCounter || result.equals("CHALLENGE_FAILED")) {
				return false;
			}

			messageCounter++;

			//---- BANK AUTH
			
			// Enviar nonce para o banco
			byte[] nonce = EncryptionUtils.generateNonce();
            MsgSequence nonceMsg = new MsgSequence(nonce, messageCounter);
            byte[] encryptedNonceMessage = EncryptionUtils.rsaEncrypt(CommUtils.serializeBytes(nonceMsg), authBank);

			out.writeObject(encryptedNonceMessage);
            messageCounter++;
			
			// Receber nonce do banco
            byte[] nonceEncryptedMine = (byte[]) in.readObject();
			byte[] nonceDecryptedMine = EncryptionUtils.rsaDecrypt(nonceEncryptedMine, privateKey);
			MsgSequence nonceDecryptedMsgMine = (MsgSequence) CommUtils.deserializeBytes(nonceDecryptedMine);

			if (nonceDecryptedMsgMine.getSeqNumber() != messageCounter) {
				return false;
			}

			messageCounter++;
			
			// Verificar decrypt do banco
			if (!Arrays.equals(nonce, nonceDecryptedMsgMine.getMsg())) {
				MsgSequence challengeResultMine = new MsgSequence(CommUtils.serializeBytes("CHALLENGE_FAILED"), messageCounter);
				out.writeObject(challengeResultMine);

				return false;
			}

			MsgSequence challengeResultMine = new MsgSequence(CommUtils.serializeBytes("CHALLENGE_PASSED"), messageCounter);
			out.writeObject(challengeResultMine);

			messageCounter++;
		} catch(SocketTimeoutException e) {
			System.exit(63);
		} catch(Exception e) {
			return false; 
		} 
			
		return true;
	}

	private SecretKey clientDH(ObjectInputStream in, ObjectOutputStream out, PublicKey authBank, PrivateKey privateKey) {
		SecretKey secretKey = null;

		try {
			// Criar chaves DH
			KeyPairGenerator clientKP = KeyPairGenerator.getInstance("DH");
	        clientKP.initialize(2048);

	        KeyPair clientDHKeyPair = clientKP.generateKeyPair();
	        byte[] clientDHPubKey = clientDHKeyPair.getPublic().getEncoded();
	        
	        // Receber chave publica DH do bank
			MsgSequence bankDHPubKeyMsg = (MsgSequence) in.readObject();

			if (bankDHPubKeyMsg.getSeqNumber() != messageCounter) {
				return null;
			}

			messageCounter++;

			byte[] bankDHPubKey = bankDHPubKeyMsg.getMsg();

			//Fazer hash da chave DH publica do bank
			byte[] bankDHPubKeyHash = EncryptionUtils.hash(bankDHPubKey);
			
			//Receber signed hash da chave DH publica do bank
			MsgSequence bankDHPubKeyHashSignedMsg = (MsgSequence) in.readObject();

			if (bankDHPubKeyHashSignedMsg.getSeqNumber() != messageCounter) {
				return null;
			}

			messageCounter++;

			byte[] bankDHPubKeyHashSigned = bankDHPubKeyHashSignedMsg.getMsg();
			
			// Verificar a signature do bank na chave
			if (!EncryptionUtils.verifySignature(bankDHPubKeyHash, bankDHPubKeyHashSigned, authBank)) {
				return null;
			}
			
			// Enviar chave publica DH ao bank
			MsgSequence messageDhPublicKey = new MsgSequence(clientDHPubKey, messageCounter);

	        out.writeObject(messageDhPublicKey);
	        messageCounter++;
	        
	        // Enviar signed hash da chave DH publica ao bank
	        byte[] clientDHPubKeyHash = EncryptionUtils.hash(clientDHPubKey);
	        byte[] clientDHPubKeyHashSigned = EncryptionUtils.sign(clientDHPubKeyHash, privateKey);
	        MsgSequence clientDHPubKeyHashSignedMsg = new MsgSequence(clientDHPubKeyHashSigned, messageCounter);
			
	        out.writeObject(clientDHPubKeyHashSignedMsg);
	        messageCounter++;
	        
	        secretKey = EncryptionUtils.createSessionKey(clientDHKeyPair.getPrivate(), bankDHPubKey);
		} catch(SocketTimeoutException e) {
			System.exit(63);
	    } catch (Exception e) {
			System.exit(255);
		}

		return secretKey;
	}

}
