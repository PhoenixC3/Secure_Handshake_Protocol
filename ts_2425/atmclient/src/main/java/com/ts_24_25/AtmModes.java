package com.ts_24_25;

import java.io.File;
import java.io.FileInputStream;
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
import java.util.ArrayList;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AtmModes {
	private int sequenceNumber;

    public void createAccount(ClientRequestMsg requestMessage, ObjectInputStream in, ObjectOutputStream out, PublicKey authBank) {
		sequenceNumber = 0;

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

			byte[] pubKeyAesEncrypted = EncryptionUtils.encryptAndHmac(publicKey.getEncoded(), aesKey);
			byte[] rsaEncyptedAesKey = EncryptionUtils.rsaEncrypt(aesKey.getEncoded(), authBank);

			//Enviar chave aes para o banco
			MsgSequence aesKeyMsg = new MsgSequence(rsaEncyptedAesKey, sequenceNumber);

			out.writeObject(aesKeyMsg);
			sequenceNumber++;

			//Enviar chave publica para o banco
			MsgSequence pubKeyMsg = new MsgSequence(pubKeyAesEncrypted, sequenceNumber);

			out.writeObject(pubKeyMsg);
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

				System.out.println(new String(responseMsg.getMsg()));
			} else {
				File cfile = new File(requestMessage.getCardFile());

				if (cfile.exists()) { 
					cfile.delete();
				}

				System.exit(255);
			}
		} catch (SocketTimeoutException e) {
			File cfile = new File(requestMessage.getCardFile());

			if (cfile.exists()) { 
				cfile.delete();
			}

			System.exit(63);
		} catch (IOException e) {
			File cfile = new File(requestMessage.getCardFile());

			if (cfile.exists()) { 
				cfile.delete();
			}

			System.exit(255);
		}
    }

	public void deposit(ClientRequestMsg requestMessage, ObjectInputStream in, ObjectOutputStream out, PublicKey authBank) {
		sequenceNumber = 0;

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

			byte[] pubKeyAesEncrypted = EncryptionUtils.encryptAndHmac(publicKey.getEncoded(), aesKey);
			byte[] rsaEncyptedAesKey = EncryptionUtils.rsaEncrypt(aesKey.getEncoded(), authBank);

			//Enviar chave aes para o banco
			MsgSequence aesKeyMsg = new MsgSequence(rsaEncyptedAesKey, sequenceNumber);

			out.writeObject(aesKeyMsg);
			sequenceNumber++;

			//Enviar chave publica para o banco
			MsgSequence pubKeyMsg = new MsgSequence(pubKeyAesEncrypted, sequenceNumber);

			out.writeObject(pubKeyMsg);
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

				System.out.println(new String(responseMsg.getMsg()));
			} else {
				System.exit(255);
			}
		} catch (SocketTimeoutException e) {
			System.exit(63);
		} catch (IOException e) {
			System.exit(255);
		}
    }

	public void withdraw(ClientRequestMsg requestMessage, ObjectInputStream in, ObjectOutputStream out, PublicKey authBank) {
		sequenceNumber = 0;

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

			byte[] pubKeyAesEncrypted = EncryptionUtils.encryptAndHmac(publicKey.getEncoded(), aesKey);
			byte[] rsaEncyptedAesKey = EncryptionUtils.rsaEncrypt(aesKey.getEncoded(), authBank);

			//Enviar chave aes para o banco
			MsgSequence aesKeyMsg = new MsgSequence(rsaEncyptedAesKey, sequenceNumber);

			out.writeObject(aesKeyMsg);
			sequenceNumber++;

			//Enviar chave publica para o banco
			MsgSequence pubKeyMsg = new MsgSequence(pubKeyAesEncrypted, sequenceNumber);

			out.writeObject(pubKeyMsg);
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

				System.out.println(new String(responseMsg.getMsg()));
			} else {
				System.exit(255);
			}
		} catch (SocketTimeoutException e) {
			System.exit(63);
		} catch (IOException e) {
			System.exit(255);
		}
    }

	public void balance(ClientRequestMsg requestMessage, ObjectInputStream in, ObjectOutputStream out, PublicKey authBank) {
		sequenceNumber = 0;

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

			byte[] pubKeyAesEncrypted = EncryptionUtils.encryptAndHmac(publicKey.getEncoded(), aesKey);
			byte[] rsaEncyptedAesKey = EncryptionUtils.rsaEncrypt(aesKey.getEncoded(), authBank);

			//Enviar chave aes para o banco
			MsgSequence aesKeyMsg = new MsgSequence(rsaEncyptedAesKey, sequenceNumber);

			out.writeObject(aesKeyMsg);
			sequenceNumber++;

			//Enviar chave publica para o banco
			MsgSequence pubKeyMsg = new MsgSequence(pubKeyAesEncrypted, sequenceNumber);

			out.writeObject(pubKeyMsg);
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

				System.out.println(new String(responseMsg.getMsg()));
			} else {
				System.exit(255);
			}
		} catch (SocketTimeoutException e) {
			System.exit(63);
		} catch (IOException e) {
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
			MsgSequence aesDHPubKeyMsg = (MsgSequence) in.readObject();

			if (aesDHPubKeyMsg.getSeqNumber() != sequenceNumber) {
				return null;
			}

			sequenceNumber++;

			byte[] bankAesDHPubKey = aesDHPubKeyMsg.getMsg();
			byte[] bankAesDHPubKeyDecoded = EncryptionUtils.rsaDecrypt(bankAesDHPubKey, privateKey);
			SecretKey aesKeyBank = new SecretKeySpec(bankAesDHPubKeyDecoded, "AES");

			// Receber DH
			MsgSequence bankDHPubKeyMsg = (MsgSequence) in.readObject();
			
			if (bankDHPubKeyMsg.getSeqNumber() != sequenceNumber) {
				return null;
			}

			sequenceNumber++;

			byte[] bankDHPubKey = bankDHPubKeyMsg.getMsg();
			byte[] bankDHPubKeyDecoded = EncryptionUtils.decryptAndVerifyHmac(bankDHPubKey, aesKeyBank);

			// ------------Fazer hash da chave DH publica do bank
			byte[] bankDHPubKeyHash = EncryptionUtils.hash(bankDHPubKeyDecoded);
			
			// ------------Receber signed hash da chave DH publica do bank
			MsgSequence bankDHPubKeyHashSignedMsg = (MsgSequence) in.readObject();

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
			byte[] rsaEncyptedAesKey = EncryptionUtils.rsaEncrypt(aesKey.getEncoded(), authBank);
			MsgSequence aesKeyMsg = new MsgSequence(rsaEncyptedAesKey, sequenceNumber);

			out.writeObject(aesKeyMsg);
			sequenceNumber++;

			//Envia DH pub key para o ATM
			byte[] dhKeyAesEncrypted = EncryptionUtils.encryptAndHmac(clientDHPubKey, aesKey);
			MsgSequence dhKeyAesEncryptedMsg = new MsgSequence(dhKeyAesEncrypted, sequenceNumber);

			out.writeObject(dhKeyAesEncryptedMsg);
			sequenceNumber++;
	        
	        // -------------Enviar signed hash da chave DH publica ao bank
	        byte[] clientDHPubKeyHash = EncryptionUtils.hash(clientDHPubKey);
	        byte[] clientDHPubKeyHashSigned = EncryptionUtils.sign(clientDHPubKeyHash, privateKey);
	        MsgSequence clientDHPubKeyHashSignedMsg = new MsgSequence(clientDHPubKeyHashSigned, sequenceNumber);
			
	        out.writeObject(clientDHPubKeyHashSignedMsg);
	        sequenceNumber++;
	        
	        secretKey = EncryptionUtils.createSessionKey(clientDHKeyPair.getPrivate(), bankDHPubKeyDecoded);

			// ----------------Enviar signed hash da session key ao bank
			byte[] sessionKeyHash = EncryptionUtils.hash(secretKey.getEncoded());
			byte[] sessionKeyHashSigned = EncryptionUtils.sign(sessionKeyHash, privateKey);
			MsgSequence sessionKeyHashSignedMsg = new MsgSequence(sessionKeyHashSigned, sequenceNumber);

			out.writeObject(sessionKeyHashSignedMsg);
			sequenceNumber++;

			// ---------------Receber signed hash da session key do bank
			MsgSequence bankSessionKeyHashSignedMsg = (MsgSequence) in.readObject();

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
