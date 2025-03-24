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
import java.util.Arrays;
import javax.crypto.SecretKey;

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
			//Enviar chave publica para o banco
			MsgSequence pubKeyMsg = new MsgSequence(CommUtils.serializeBytes(publicKey), sequenceNumber);

			out.writeObject(pubKeyMsg);
			sequenceNumber++;
        } catch (Exception e) {
            System.exit(255);
        }

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

		try {
			//Enviar o request para o banco
			String request = requestMessage.getCmdType() + " " + requestMessage.getAccount() + (requestMessage.getAmount() != null ? " " + requestMessage.getAmount() : "");

			// Encrypt and send the request
			MsgSequence msg = new MsgSequence(CommUtils.serializeBytes(request), sequenceNumber);

			byte[] cypherTextAndHmac = EncryptionUtils.encryptAndHmac(CommUtils.serializeBytes(msg), secretKey);

			out.write(cypherTextAndHmac);
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
				e.printStackTrace();
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

	public void deposit(ClientRequestMsg requestMessage, String account, ObjectInputStream in, ObjectOutputStream out, PublicKey authBank, PrivateKey privateKey) {
		sequenceNumber = 0;

		KeyPair keypair = loadCardFile(requestMessage.getCardFile());

		if (keypair == null) {
			System.exit(255);
		}

		PublicKey publicKey = keypair.getPublic();

		// Verificar balance
		if (Double.parseDouble(requestMessage.getAmount()) < 0.00) {
			System.exit(255);
		}

		//-------------------Autenticacao mutua e DH

		try {
			//Enviar chave publica para o banco
			MsgSequence pubKeyMsg = new MsgSequence(CommUtils.serializeBytes(publicKey), sequenceNumber);

			out.writeObject(pubKeyMsg);
			sequenceNumber++;
        } catch (Exception e) {
            System.exit(255);
        }

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

		try {
			//Enviar o request para o banco
			String request = requestMessage.getCmdType() + " " + requestMessage.getAccount() + (requestMessage.getAmount() != null ? " " + requestMessage.getAmount() : "");

			// Encrypt and send the request
			MsgSequence msg = new MsgSequence(CommUtils.serializeBytes(request), sequenceNumber);

			byte[] cypherTextAndHmac = EncryptionUtils.encryptAndHmac(CommUtils.serializeBytes(msg), secretKey);

			out.write(cypherTextAndHmac);
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
				e.printStackTrace();
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

	public void withdraw(ClientRequestMsg requestMessage, String account, ObjectInputStream in, ObjectOutputStream out, PublicKey authBank, PrivateKey privateKey) {
		sequenceNumber = 0;

		KeyPair keypair = loadCardFile(requestMessage.getCardFile());

		if (keypair == null) {
			System.exit(255);
		}

		PublicKey publicKey = keypair.getPublic();

		// Verificar balance
		if (Double.parseDouble(requestMessage.getAmount()) < 0.00) {
			System.exit(255);
		}

		//-------------------Autenticacao mutua e DH

		try {
			//Enviar chave publica para o banco
			MsgSequence pubKeyMsg = new MsgSequence(CommUtils.serializeBytes(publicKey), sequenceNumber);

			out.writeObject(pubKeyMsg);
			sequenceNumber++;
        } catch (Exception e) {
            System.exit(255);
        }

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

		try {
			//Enviar o request para o banco
			String request = requestMessage.getCmdType() + " " + requestMessage.getAccount() + (requestMessage.getAmount() != null ? " " + requestMessage.getAmount() : "");

			// Encrypt and send the request
			MsgSequence msg = new MsgSequence(CommUtils.serializeBytes(request), sequenceNumber);

			byte[] cypherTextAndHmac = EncryptionUtils.encryptAndHmac(CommUtils.serializeBytes(msg), secretKey);

			out.write(cypherTextAndHmac);
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
				e.printStackTrace();
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

	public void balance(ClientRequestMsg requestMessage, String account, ObjectInputStream in, ObjectOutputStream out, PublicKey authBank, PrivateKey privateKey) {
		sequenceNumber = 0;

		KeyPair keypair = loadCardFile(requestMessage.getCardFile());

		if (keypair == null) {
			System.exit(255);
		}

		PublicKey publicKey = keypair.getPublic();

		//-------------------Autenticacao mutua e DH

		try {
			//Enviar chave publica para o banco
			MsgSequence pubKeyMsg = new MsgSequence(CommUtils.serializeBytes(publicKey), sequenceNumber);

			out.writeObject(pubKeyMsg);
			sequenceNumber++;
        } catch (Exception e) {
            System.exit(255);
        }

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

		try {
			//Enviar o request para o banco
			String request = requestMessage.getCmdType() + " " + requestMessage.getAccount() + (requestMessage.getAmount() != null ? " " + requestMessage.getAmount() : "");

			// Encrypt and send the request
			MsgSequence msg = new MsgSequence(CommUtils.serializeBytes(request), sequenceNumber);

			byte[] cypherTextAndHmac = EncryptionUtils.encryptAndHmac(CommUtils.serializeBytes(msg), secretKey);

			out.write(cypherTextAndHmac);
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
				e.printStackTrace();
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

    private boolean clientNonceExchange(ObjectInputStream in, ObjectOutputStream out, PublicKey authBank, PrivateKey privateKey) {
		try {
			//---- CLIENT AUTH

			// Receber nonce do banco e decrypt
			byte[] nonceEncrypted = (byte[]) in.readObject();
			byte[] nonceDecrypted = EncryptionUtils.rsaDecrypt(nonceEncrypted, privateKey);
			MsgSequence nonceDecryptedMsg = (MsgSequence) CommUtils.deserializeBytes(nonceDecrypted);

			if (nonceDecryptedMsg.getSeqNumber() != sequenceNumber) {
				return false;
			}

			sequenceNumber++;
			
			// Encrypt e reenviar para o banco
			MsgSequence nonceToSend = new MsgSequence(nonceDecryptedMsg.getMsg(), sequenceNumber);
			byte[] encryptedBytes = EncryptionUtils.rsaEncrypt(CommUtils.serializeBytes(nonceToSend), authBank);

			out.writeObject(encryptedBytes);
			sequenceNumber++;
			
			//Resposta do banco
			MsgSequence challengeResult = (MsgSequence) in.readObject();
			String result = (String) CommUtils.deserializeBytes(challengeResult.getMsg());
			
			if (challengeResult.getSeqNumber() != sequenceNumber || result.equals("CHALLENGE_FAILED")) {
				return false;
			}

			sequenceNumber++;

			//---- BANK AUTH
			
			// Enviar nonce para o banco
			byte[] nonce = EncryptionUtils.generateNonce();
            MsgSequence nonceMsg = new MsgSequence(nonce, sequenceNumber);
            byte[] encryptedNonceMessage = EncryptionUtils.rsaEncrypt(CommUtils.serializeBytes(nonceMsg), authBank);

			out.writeObject(encryptedNonceMessage);
            sequenceNumber++;
			
			// Receber nonce do banco
            byte[] nonceEncryptedMine = (byte[]) in.readObject();
			byte[] nonceDecryptedMine = EncryptionUtils.rsaDecrypt(nonceEncryptedMine, privateKey);
			MsgSequence nonceDecryptedMsgMine = (MsgSequence) CommUtils.deserializeBytes(nonceDecryptedMine);

			if (nonceDecryptedMsgMine.getSeqNumber() != sequenceNumber) {
				return false;
			}

			sequenceNumber++;
			
			// Verificar decrypt do banco
			if (!Arrays.equals(nonce, nonceDecryptedMsgMine.getMsg())) {
				MsgSequence challengeResultMine = new MsgSequence(CommUtils.serializeBytes("CHALLENGE_FAILED"), sequenceNumber);
				out.writeObject(challengeResultMine);

				return false;
			}

			MsgSequence challengeResultMine = new MsgSequence(CommUtils.serializeBytes("CHALLENGE_PASSED"), sequenceNumber);
			out.writeObject(challengeResultMine);

			sequenceNumber++;
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

			if (bankDHPubKeyMsg.getSeqNumber() != sequenceNumber) {
				return null;
			}

			sequenceNumber++;

			byte[] bankDHPubKey = bankDHPubKeyMsg.getMsg();

			//Fazer hash da chave DH publica do bank
			byte[] bankDHPubKeyHash = EncryptionUtils.hash(bankDHPubKey);
			
			//Receber signed hash da chave DH publica do bank
			MsgSequence bankDHPubKeyHashSignedMsg = (MsgSequence) in.readObject();

			if (bankDHPubKeyHashSignedMsg.getSeqNumber() != sequenceNumber) {
				return null;
			}

			sequenceNumber++;

			byte[] bankDHPubKeyHashSigned = bankDHPubKeyHashSignedMsg.getMsg();
			
			// Verificar a signature do bank na chave
			if (!EncryptionUtils.verifySignature(bankDHPubKeyHash, bankDHPubKeyHashSigned, authBank)) {
				return null;
			}
			
			// Enviar chave publica DH ao bank
			MsgSequence messageDhPublicKey = new MsgSequence(clientDHPubKey, sequenceNumber);

	        out.writeObject(messageDhPublicKey);
	        sequenceNumber++;
	        
	        // Enviar signed hash da chave DH publica ao bank
	        byte[] clientDHPubKeyHash = EncryptionUtils.hash(clientDHPubKey);
	        byte[] clientDHPubKeyHashSigned = EncryptionUtils.sign(clientDHPubKeyHash, privateKey);
	        MsgSequence clientDHPubKeyHashSignedMsg = new MsgSequence(clientDHPubKeyHashSigned, sequenceNumber);
			
	        out.writeObject(clientDHPubKeyHashSignedMsg);
	        sequenceNumber++;
	        
	        secretKey = EncryptionUtils.createSessionKey(clientDHKeyPair.getPrivate(), bankDHPubKey);
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
		} catch (IOException | ClassNotFoundException e) {
			System.exit(255);
		}

		return keypair; 
	}

}
