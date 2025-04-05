package com.ts_24_25;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AtmModes {
	private long sequenceNumber;

    public void createAccount(ClientRequestMsg requestMessage, ObjectInputStream in, ObjectOutputStream out, PublicKey authBank) {
		sequenceNumber = new SecureRandom().nextLong();

		// Verificar balance
		if (Double.parseDouble(requestMessage.getAmount()) < 10.00) {
			System.exit(255);
		}

		//Verificar se card file ja existe
        Path path = Paths.get(requestMessage.getCardFile());
		if (Files.exists(path)) {
			System.exit(255);
		}

        //Criar chaves do cliente
        PublicKey publicKey = null;
		PrivateKey privateKey = null;

        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);

            KeyPair kp = kpg.generateKeyPair();
            privateKey = kp.getPrivate();
            publicKey = kp.getPublic();

			//Criar card file
			createCardFile(requestMessage.getCardFile(), kp);
        } catch (NoSuchAlgorithmException e) {
			File cfile = new File(requestMessage.getCardFile());

			if (cfile.exists()) { 
				cfile.delete();
			}

            System.exit(255);
        }

        //-------------------Autenticacao mutua e DH

		try {
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(256);
			SecretKey aesKey = keyGen.generateKey();

			//Enviar chave AES para o banco
			MsgSequence aesKeyMsg = new MsgSequence(aesKey.getEncoded(), sequenceNumber);
			byte[] rsaEncyptedAesKeyMsg = EncryptionUtils.rsaEncrypt(CommUtils.serializeBytes(aesKeyMsg), authBank);

			out.writeObject(rsaEncyptedAesKeyMsg);
			out.flush();

			sequenceNumber++;

			//Enviar chave publica para o banco
			MsgSequence pubKeyMsg = new MsgSequence(publicKey.getEncoded(), sequenceNumber);
			byte[] pubKeyAesEncryptedMsg = EncryptionUtils.encryptAndHmac(CommUtils.serializeBytes(pubKeyMsg), aesKey);

			out.writeObject(pubKeyAesEncryptedMsg);
			out.flush();

			sequenceNumber++;
        } catch (Exception e) {
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

		try {
			//Enviar o request para o banco
			String request = requestMessage.getCmdType() + " " + requestMessage.getAccount() + (requestMessage.getAmount() != null ? " " + requestMessage.getAmount() : "");

			// Encrypt and send the request
			MsgSequence msg = new MsgSequence(CommUtils.serializeBytes(request), sequenceNumber);

			byte[] cypherTextAndHmac = EncryptionUtils.encryptAndHmac(CommUtils.serializeBytes(msg), secretKey);

			out.writeObject(cypherTextAndHmac);
			out.flush();

			sequenceNumber++;

			//Enviar hash do card file para o banco
			byte[] cardFileHash = EncryptionUtils.hash(CommUtils.serializeBytes(new File(requestMessage.getCardFile())));
			MsgSequence cfhMsg = new MsgSequence(cardFileHash, sequenceNumber);

			byte[] cfhMsgEnc = EncryptionUtils.encryptAndHmac(CommUtils.serializeBytes(cfhMsg), secretKey);

			out.writeObject(cfhMsgEnc);
			out.flush();

			sequenceNumber++;

			//Receber a resposta do banco
			ArrayList<Byte> byteList = new ArrayList<>();
			do {
				byteList.add((byte) in.read());
			} while (in.available() != 0);

			byte[] response = new byte[byteList.size()];
			for (int i = 0; i < byteList.size(); i++) {
				response[i] = byteList.get(i);
			}

			byte[] plaintext = EncryptionUtils.decryptAndVerifyHmac(response, secretKey);

			MsgSequence responseMsg = null;
			try {
				responseMsg = (MsgSequence) CommUtils.deserializeBytes(plaintext);
			} catch (Exception e) {
				System.exit(255);
			}

			if (responseMsg != null) {
				// Verify the sequence number
				if (responseMsg.getSeqNumber() != sequenceNumber) {
					File cfile = new File(requestMessage.getCardFile());

					if (cfile.exists()) { 
						cfile.delete();
					}

					System.exit(255);
				}

				sequenceNumber++;

				System.out.println(new String(responseMsg.getMsg()) + "\n");

				System.exit(0);
			} else {
				File cfile = new File(requestMessage.getCardFile());

				if (cfile.exists()) { 
					cfile.delete();
				}

				System.exit(255);
			}
		} catch (IOException e) {
			File cfile = new File(requestMessage.getCardFile());

			if (cfile.exists()) { 
				cfile.delete();
			}

			System.exit(63);
		} catch (Exception e) {
			File cfile = new File(requestMessage.getCardFile());

			if (cfile.exists()) { 
				cfile.delete();
			}

			System.exit(255);
		}
    }

	public void deposit(ClientRequestMsg requestMessage, ObjectInputStream in, ObjectOutputStream out, PublicKey authBank) {
		sequenceNumber = new SecureRandom().nextLong();

		// Verificar balance
		if (Double.parseDouble(requestMessage.getAmount()) <= 0.00) {
			System.exit(255);
		}

		KeyPair kp = loadCardFile(requestMessage.getCardFile());

		if (kp == null) {
			System.exit(255);
		}

		PublicKey publicKey = kp.getPublic();
		PrivateKey privateKey = kp.getPrivate();

        //-------------------Autenticacao mutua e DH

		try {
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(256);
			SecretKey aesKey = keyGen.generateKey();

			//Enviar chave AES para o banco
			MsgSequence aesKeyMsg = new MsgSequence(aesKey.getEncoded(), sequenceNumber);
			byte[] rsaEncyptedAesKeyMsg = EncryptionUtils.rsaEncrypt(CommUtils.serializeBytes(aesKeyMsg), authBank);

			out.writeObject(rsaEncyptedAesKeyMsg);
			out.flush();

			sequenceNumber++;

			//Enviar chave publica para o banco
			MsgSequence pubKeyMsg = new MsgSequence(publicKey.getEncoded(), sequenceNumber);
			byte[] pubKeyAesEncryptedMsg = EncryptionUtils.encryptAndHmac(CommUtils.serializeBytes(pubKeyMsg), aesKey);

			out.writeObject(pubKeyAesEncryptedMsg);
			out.flush();

			sequenceNumber++;
        } catch (Exception e) {
            System.exit(255);
        }

        //Diffie Hellman
        SecretKey secretKey = clientDH(in, out, authBank, privateKey);
		if (secretKey == null) {
			System.exit(255);
		}

        //-------------------Fim de autenticacao mutua

		try {
			//Enviar o request para o banco
			String request = requestMessage.getCmdType() + " " + requestMessage.getAccount() + (requestMessage.getAmount() != null ? " " + requestMessage.getAmount() : "");

			// Encrypt and send the request
			MsgSequence msg = new MsgSequence(CommUtils.serializeBytes(request), sequenceNumber);

			byte[] cypherTextAndHmac = EncryptionUtils.encryptAndHmac(CommUtils.serializeBytes(msg), secretKey);

			out.writeObject(cypherTextAndHmac);
			out.flush();

			sequenceNumber++;

			//Enviar hash do card file para o banco
			byte[] cardFileHash = EncryptionUtils.hash(CommUtils.serializeBytes(new File(requestMessage.getCardFile())));
			MsgSequence cfhMsg = new MsgSequence(cardFileHash, sequenceNumber);

			byte[] cfhMsgEnc = EncryptionUtils.encryptAndHmac(CommUtils.serializeBytes(cfhMsg), secretKey);

			out.writeObject(cfhMsgEnc);
			out.flush();

			sequenceNumber++;

			//Receber a resposta do banco
			ArrayList<Byte> byteList = new ArrayList<>();
			do {
				byteList.add((byte) in.read());
			} while (in.available() != 0);

			byte[] response = new byte[byteList.size()];
			for (int i = 0; i < byteList.size(); i++) {
				response[i] = byteList.get(i);
			}

			byte[] plaintext = EncryptionUtils.decryptAndVerifyHmac(response, secretKey);

			MsgSequence responseMsg = null;
			try {
				responseMsg = (MsgSequence) CommUtils.deserializeBytes(plaintext);
			} catch (Exception e) {
				System.exit(255);
			}

			if (responseMsg != null) {
				// Verify the sequence number
				if (responseMsg.getSeqNumber() != sequenceNumber) {
					System.exit(255);
				}

				sequenceNumber++;

				System.out.println(new String(responseMsg.getMsg()) + "\n");

				System.exit(0);
			} else {
				System.exit(255);
			}
		} catch (SocketTimeoutException e) {
			System.exit(63);
		} catch (Exception e) {
			System.exit(255);
		}
    }

	public void withdraw(ClientRequestMsg requestMessage, ObjectInputStream in, ObjectOutputStream out, PublicKey authBank) {
		sequenceNumber = new SecureRandom().nextLong();

		// Verificar balance
		if (Double.parseDouble(requestMessage.getAmount()) <= 0.00) {
			System.exit(255);
		}

		KeyPair kp = loadCardFile(requestMessage.getCardFile());

		if (kp == null) {
			System.exit(255);
		}

		PublicKey publicKey = kp.getPublic();
		PrivateKey privateKey = kp.getPrivate();

        //-------------------Autenticacao mutua e DH

		try {
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(256);
			SecretKey aesKey = keyGen.generateKey();

			//Enviar chave AES para o banco
			MsgSequence aesKeyMsg = new MsgSequence(aesKey.getEncoded(), sequenceNumber);
			byte[] rsaEncyptedAesKeyMsg = EncryptionUtils.rsaEncrypt(CommUtils.serializeBytes(aesKeyMsg), authBank);

			out.writeObject(rsaEncyptedAesKeyMsg);
			out.flush();

			sequenceNumber++;

			//Enviar chave publica para o banco
			MsgSequence pubKeyMsg = new MsgSequence(publicKey.getEncoded(), sequenceNumber);
			byte[] pubKeyAesEncryptedMsg = EncryptionUtils.encryptAndHmac(CommUtils.serializeBytes(pubKeyMsg), aesKey);

			out.writeObject(pubKeyAesEncryptedMsg);
			out.flush();

			sequenceNumber++;
        } catch (Exception e) {
            System.exit(255);
        }

        //Diffie Hellman
        SecretKey secretKey = clientDH(in, out, authBank, privateKey);
		if (secretKey == null) {
			System.exit(255);
		}

        //-------------------Fim de autenticacao mutua

		try {
			//Enviar o request para o banco
			String request = requestMessage.getCmdType() + " " + requestMessage.getAccount() + (requestMessage.getAmount() != null ? " " + requestMessage.getAmount() : "");

			// Encrypt and send the request
			MsgSequence msg = new MsgSequence(CommUtils.serializeBytes(request), sequenceNumber);

			byte[] cypherTextAndHmac = EncryptionUtils.encryptAndHmac(CommUtils.serializeBytes(msg), secretKey);

			out.writeObject(cypherTextAndHmac);
			out.flush();

			sequenceNumber++;

			//Enviar hash do card file para o banco
			byte[] cardFileHash = EncryptionUtils.hash(CommUtils.serializeBytes(new File(requestMessage.getCardFile())));
			MsgSequence cfhMsg = new MsgSequence(cardFileHash, sequenceNumber);

			byte[] cfhMsgEnc = EncryptionUtils.encryptAndHmac(CommUtils.serializeBytes(cfhMsg), secretKey);

			out.writeObject(cfhMsgEnc);
			out.flush();

			sequenceNumber++;

			//Receber a resposta do banco
			ArrayList<Byte> byteList = new ArrayList<>();
			do {
				byteList.add((byte) in.read());
			} while (in.available() != 0);

			byte[] response = new byte[byteList.size()];
			for (int i = 0; i < byteList.size(); i++) {
				response[i] = byteList.get(i);
			}

			byte[] plaintext = EncryptionUtils.decryptAndVerifyHmac(response, secretKey);

			MsgSequence responseMsg = null;
			try {
				responseMsg = (MsgSequence) CommUtils.deserializeBytes(plaintext);
			} catch (Exception e) {
				System.exit(255);
			}

			if (responseMsg != null) {
				// Verify the sequence number
				if (responseMsg.getSeqNumber() != sequenceNumber) {
					System.exit(255);
				}

				sequenceNumber++;

				System.out.println(new String(responseMsg.getMsg()) + "\n");

				System.exit(0);
			} else {
				System.exit(255);
			}
		} catch (SocketTimeoutException e) {
			System.exit(63);
		} catch (Exception e) {
			System.exit(255);
		}
    }

	public void balance(ClientRequestMsg requestMessage, ObjectInputStream in, ObjectOutputStream out, PublicKey authBank) {
		sequenceNumber = new SecureRandom().nextLong();

		KeyPair kp = loadCardFile(requestMessage.getCardFile());

		if (kp == null) {
			System.exit(255);
		}

		PublicKey publicKey = kp.getPublic();
		PrivateKey privateKey = kp.getPrivate();

        //-------------------Autenticacao mutua e DH

		try {
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(256);
			SecretKey aesKey = keyGen.generateKey();

			//Enviar chave AES para o banco
			MsgSequence aesKeyMsg = new MsgSequence(aesKey.getEncoded(), sequenceNumber);
			byte[] rsaEncyptedAesKeyMsg = EncryptionUtils.rsaEncrypt(CommUtils.serializeBytes(aesKeyMsg), authBank);

			out.writeObject(rsaEncyptedAesKeyMsg);
			out.flush();

			sequenceNumber++;

			//Enviar chave publica para o banco
			MsgSequence pubKeyMsg = new MsgSequence(publicKey.getEncoded(), sequenceNumber);
			byte[] pubKeyAesEncryptedMsg = EncryptionUtils.encryptAndHmac(CommUtils.serializeBytes(pubKeyMsg), aesKey);

			out.writeObject(pubKeyAesEncryptedMsg);
			out.flush();

			sequenceNumber++;
        } catch (Exception e) {
            System.exit(255);
        }

        //Diffie Hellman
        SecretKey secretKey = clientDH(in, out, authBank, privateKey);
		if (secretKey == null) {
			System.exit(255);
		}

        //-------------------Fim de autenticacao mutua

		try {
			//Enviar o request para o banco
			String request = requestMessage.getCmdType() + " " + requestMessage.getAccount() + (requestMessage.getAmount() != null ? " " + requestMessage.getAmount() : "");

			// Encrypt and send the request
			MsgSequence msg = new MsgSequence(CommUtils.serializeBytes(request), sequenceNumber);

			byte[] cypherTextAndHmac = EncryptionUtils.encryptAndHmac(CommUtils.serializeBytes(msg), secretKey);

			out.writeObject(cypherTextAndHmac);
			out.flush();

			sequenceNumber++;

			//Enviar hash do card file para o banco
			byte[] cardFileHash = EncryptionUtils.hash(CommUtils.serializeBytes(new File(requestMessage.getCardFile())));
			MsgSequence cfhMsg = new MsgSequence(cardFileHash, sequenceNumber);

			byte[] cfhMsgEnc = EncryptionUtils.encryptAndHmac(CommUtils.serializeBytes(cfhMsg), secretKey);

			out.writeObject(cfhMsgEnc);
			out.flush();

			sequenceNumber++;

			//Receber a resposta do banco
			ArrayList<Byte> byteList = new ArrayList<>();
			do {
				byteList.add((byte) in.read());
			} while (in.available() != 0);

			byte[] response = new byte[byteList.size()];
			for (int i = 0; i < byteList.size(); i++) {
				response[i] = byteList.get(i);
			}

			byte[] plaintext = EncryptionUtils.decryptAndVerifyHmac(response, secretKey);

			MsgSequence responseMsg = null;
			try {
				responseMsg = (MsgSequence) CommUtils.deserializeBytes(plaintext);
			} catch (Exception e) {
				System.exit(255);
			}

			if (responseMsg != null) {
				// Verify the sequence number
				if (responseMsg.getSeqNumber() != sequenceNumber) {
					System.exit(255);
				}

				sequenceNumber++;

				System.out.println(new String(responseMsg.getMsg()) + "\n");

				System.exit(0);
			} else {
				System.exit(255);
			}
		} catch (SocketTimeoutException e) {
			System.exit(63);
		} catch (Exception e) {
			System.exit(255);
		}
    }

	private SecretKey clientDH(ObjectInputStream in, ObjectOutputStream out, PublicKey authBank, PrivateKey privateKey) {
		SecretKey secretKey = null;

		try {
			// -------------Criar chaves DH
			KeyPairGenerator clientKP = KeyPairGenerator.getInstance("DH");
	        clientKP.initialize(2048);

	        KeyPair clientDHKeyPair = clientKP.generateKeyPair();
	        byte[] clientDHPubKey = clientDHKeyPair.getPublic().getEncoded();
	        
	        // -----------Receber chave publica DH do bank

			//Receber AES key do bank
			byte[] aesDHPubKey = (byte[]) in.readObject();
			byte[] aesDHPubKeyDecoded = EncryptionUtils.rsaDecrypt(aesDHPubKey, privateKey);
			MsgSequence aesDHPubKeyMsg = (MsgSequence) CommUtils.deserializeBytes(aesDHPubKeyDecoded);

			if (aesDHPubKeyMsg.getSeqNumber() != sequenceNumber) {
				return null;
			}

			sequenceNumber++;

			SecretKey aesKeyBank = new SecretKeySpec(aesDHPubKeyMsg.getMsg(), "AES");

			// Receber DH
			byte[] bankDHPubKey = (byte[]) in.readObject();
			byte[] bankDHPubKeyDecoded = EncryptionUtils.decryptAndVerifyHmac(bankDHPubKey, aesKeyBank);
			MsgSequence bankDHPubKeyMsg = (MsgSequence) CommUtils.deserializeBytes(bankDHPubKeyDecoded);
			
			if (bankDHPubKeyMsg.getSeqNumber() != sequenceNumber) {
				return null;
			}

			sequenceNumber++;

			// ------------Fazer hash da chave DH publica do bank
			byte[] bankDHPubKeyHash = EncryptionUtils.hash(bankDHPubKeyMsg.getMsg());
			
			// ------------Receber signed hash da chave DH publica do bank
			byte[] bankDHPubKeyHashSignedRec = (byte[]) in.readObject();
			byte[] bankDHPubKeyHashSignedDecoded = EncryptionUtils.decryptAndVerifyHmac(bankDHPubKeyHashSignedRec, aesKeyBank);
			MsgSequence bankDHPubKeyHashSignedMsg = (MsgSequence) CommUtils.deserializeBytes(bankDHPubKeyHashSignedDecoded);

			if (bankDHPubKeyHashSignedMsg.getSeqNumber() != sequenceNumber) {
				return null;
			}

			sequenceNumber++;

			byte[] bankDHPubKeyHashSigned = bankDHPubKeyHashSignedMsg.getMsg();
			
			// --------------Verificar a signature do bank na chave
			if (!EncryptionUtils.verifySignature(bankDHPubKeyHash, bankDHPubKeyHashSigned, authBank)) {
				return null;
			}
			
			//-------------- ATM envia chave publica DH ao Bank

			//Criar chave AES para enviar DH Key
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(256);
			SecretKey aesKey = keyGen.generateKey();

			// Envia chave AES para o ATM
			MsgSequence aesKeyMsg = new MsgSequence(aesKey.getEncoded(), sequenceNumber);
			byte[] rsaEncyptedAesKey = EncryptionUtils.rsaEncrypt(CommUtils.serializeBytes(aesKeyMsg), authBank);

			out.writeObject(rsaEncyptedAesKey);
			out.flush();

			sequenceNumber++;

			//Envia DH pub key para o ATM
			MsgSequence clientDHPubKeyMsg = new MsgSequence(clientDHPubKey, sequenceNumber);
			byte[] dhKeyAesEncrypted = EncryptionUtils.encryptAndHmac(CommUtils.serializeBytes(clientDHPubKeyMsg), aesKey);

			out.writeObject(dhKeyAesEncrypted);
			out.flush();

			sequenceNumber++;
	        
	        // -------------Enviar signed hash da chave DH publica ao bank
	        byte[] clientDHPubKeyHash = EncryptionUtils.hash(clientDHPubKey);
	        byte[] clientDHPubKeyHashSigned = EncryptionUtils.sign(clientDHPubKeyHash, privateKey);
	        MsgSequence clientDHPubKeyHashSignedMsg = new MsgSequence(clientDHPubKeyHashSigned, sequenceNumber);
			byte[] clientDHPubKeyHashSignedMsgSend = EncryptionUtils.encryptAndHmac(CommUtils.serializeBytes(clientDHPubKeyHashSignedMsg), aesKey);
			
	        out.writeObject(clientDHPubKeyHashSignedMsgSend);
			out.flush();

	        sequenceNumber++;
	        
	        secretKey = EncryptionUtils.createSessionKey(clientDHKeyPair.getPrivate(), bankDHPubKeyMsg.getMsg());

			// ----------------Enviar signed hash da session key ao bank
			byte[] sessionKeyHash = EncryptionUtils.hash(secretKey.getEncoded());
			byte[] sessionKeyHashSigned = EncryptionUtils.sign(sessionKeyHash, privateKey);
			MsgSequence sessionKeyHashSignedMsg = new MsgSequence(sessionKeyHashSigned, sequenceNumber);
			byte[] sessionKeyHashSignedMsgSend = EncryptionUtils.encryptAndHmac(CommUtils.serializeBytes(sessionKeyHashSignedMsg), aesKey);

			out.writeObject(sessionKeyHashSignedMsgSend);
			out.flush();

			sequenceNumber++;

			// ---------------Receber signed hash da session key do bank
			byte[] bankSessionKeyHashSigned = (byte[]) in.readObject();
			byte[] bankSessionKeyHashSignedDecoded = EncryptionUtils.decryptAndVerifyHmac(bankSessionKeyHashSigned, aesKeyBank);
			MsgSequence bankSessionKeyHashSignedMsg = (MsgSequence) CommUtils.deserializeBytes(bankSessionKeyHashSignedDecoded);

			if (bankSessionKeyHashSignedMsg.getSeqNumber() != sequenceNumber) {
				return null;
			}

			sequenceNumber++;

			// -------------------Verificar a signature do bank na chave
			if (!EncryptionUtils.verifySignature(sessionKeyHash, bankSessionKeyHashSignedMsg.getMsg(), authBank)) {
				return null;
			}
			
		} catch(SocketTimeoutException e) {
			System.exit(63);
	    } catch (Exception e) {
			System.exit(255);
		}

		return secretKey;
	}

	private static void createCardFile(String cardFileName, KeyPair keypair) {
		try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(cardFileName))) {
			oos.writeObject(keypair);
			oos.flush();
		} catch (IOException e) {
			File cfile = new File(cardFileName);

			if (cfile.exists()) { 
				cfile.delete();
			}

			System.exit(255);
		} 
	}

	private static KeyPair loadCardFile(String cardFileName) {
		KeyPair keypair = null;

		try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(cardFileName))) {
			keypair = (KeyPair) ois.readObject();
		} catch (Exception e) {
			return null;
		}

		return keypair; 
	}

}
