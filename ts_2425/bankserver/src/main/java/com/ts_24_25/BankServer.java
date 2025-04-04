package com.ts_24_25;

import java.io.*;
import java.net.*;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class BankServer {
    private String port;
    private String authFile;
    private static HashMap<String, Double> accounts = new HashMap<>();
    private static PrivateKey privateKey;

    public static void main(String[] args) {
        BankServer server = new BankServer(args);
        server.start();
    }

    public BankServer(String[] args) {
        parseArgs(args);

        if (port == null) {
            port = "3000";
        }

        if (authFile == null) {
            authFile = "bank.auth";
        }

        if (authFile != null && !VerifyArgs.verifyFileNames(authFile)) {
			System.exit(255);
        }

        if (port != null && !VerifyArgs.verifyPort(port)) {
			System.exit(255);
		}

        //Criar ficheiro de auth
        try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);

			KeyPair kp = kpg.generateKeyPair();
			privateKey = kp.getPrivate();

			createAuthFile(authFile, kp.getPublic());
		} catch (Exception e) {
			System.exit(255);
		}
    }

    private void parseArgs(String[] args) {
		int i = 0; 

		while (i < args.length) {
			if (args[i].length() >= 4096) {
				System.exit(255);
			}

			String flag = null;
            String value = null;

			if (args[i].length() > 2) {
				flag = args[i].substring(0,2);
				value = args[i].substring(2);
			}

            if (flag == null) {
                flag = args[i];
            }
			
			if (flag.equals("-s")) {
				if (authFile != null) {
					System.exit(255);
				}
				if (value == null && i + 1 < args.length) {
					authFile = args[i + 1];
					i++;
				}
				else if (i + 1 >= args.length && value == null) {
					System.exit(255);
				}
				else {
					authFile = value;
				}
			}
			else if (flag.equals("-p")) {
				if (port != null) {
					System.exit(255);
				}
				if (value == null && i + 1 < args.length) {
					port = args[i + 1];
					i++;
				}
				else if (i + 1 >= args.length && value == null) {
					System.exit(255);
				}
				else {
					port = value;
				}
			}
			
			i++;
		}
	}

    private void createAuthFile(String authFileName, PublicKey publicKey) {
        File file = new File(authFile);
        if (file.exists()) {
            System.exit(255);
        }

		try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(authFileName))) {
			oos.writeObject(publicKey);
			System.out.println("created");
		} catch (Exception e) {
			System.exit(255);
		}
	}

    public void start() {
		try (ServerSocket serverSocket = new ServerSocket(Integer.parseInt(port))) {
			System.out.println("Bank server is running on port " + port + "\n");
	
			Runtime.getRuntime().addShutdownHook(new Thread(() -> {
				System.out.println("Shutting down server...");
				
				try {
					serverSocket.close();
				} catch (IOException e) {
					System.out.println("protocol_error");
				}
			}));
	
			while (true) {
				try {
					Socket sock = serverSocket.accept();
					BankThread bt = new BankThread(sock, privateKey);

					bt.start();
				} catch (SocketException e) {
					if (serverSocket.isClosed()) {
						System.out.println("Server stopped.");

						return;
					}

					System.out.println("protocol_error");
				} catch (IOException e) {
					System.out.println("protocol_error");
				}
			}
		} catch (IOException e) {
			System.out.println("protocol_error");
		}
	}
	

	public static class BankThread  extends Thread {
		private Socket socket;
		private PrivateKey privateKey;
		private ObjectInputStream in;
		private ObjectOutputStream out;
		private int sequenceNumber;

		public BankThread(Socket socket, PrivateKey privateKey) {
			this.socket = socket;
			this.privateKey = privateKey;
			this.sequenceNumber = 0;
		}

		public void run() {

			try {
				socket.setSoTimeout(10000);

				in = inputStream(socket);
				out = outputStream(socket);

				if (in == null || out == null) {
					return;
				}
				
				while (true) {
					//--------------Authentication----------------

					//Receber chave aes do cliente
					MsgSequence aesKeyMsg = (MsgSequence) in.readObject();

					if (aesKeyMsg.getSeqNumber() != sequenceNumber) {
						return;
					}

					sequenceNumber++;

					byte[] aesKeyBytesDecrypted = EncryptionUtils.rsaDecrypt(aesKeyMsg.getMsg(), privateKey);
					SecretKey aesKey = new SecretKeySpec(aesKeyBytesDecrypted, "AES");

					//Receber chave publica do cliente
					MsgSequence pubKeyMsg = (MsgSequence) in.readObject();

					if (pubKeyMsg.getSeqNumber() != sequenceNumber) {
						return;
					}

					sequenceNumber++;

					byte[] clientPublicKeyBytesDescrypted = EncryptionUtils.decryptAndVerifyHmac(pubKeyMsg.getMsg(), aesKey);

					KeyFactory keyFactory = KeyFactory.getInstance("RSA");
					X509EncodedKeySpec keySpec = new X509EncodedKeySpec(clientPublicKeyBytesDescrypted);
					PublicKey clientPublicKey = keyFactory.generatePublic(keySpec);

					//DH
					SecretKey secretKey = bankDH(clientPublicKey);
					if (secretKey == null) {
						return;
					}

					//--------------Authentication Finished----------------

					// Receives the request
					byte[] allMessage = (byte[]) in.readObject();

					// Decrypts the request
					byte[] decryptedMessage = EncryptionUtils.decryptAndVerifyHmac(allMessage, secretKey);

					// Converts the decrypted message to a string
					MsgSequence msg = null;
					try {
						msg = (MsgSequence) CommUtils.deserializeBytes(decryptedMessage);
					} catch (Exception e) {
						return;
					}

					String response = null;
					if (msg != null) {
						// Verifies the sequence number
						if (msg.getSeqNumber() != sequenceNumber) {
							return;
						}

						sequenceNumber++;
						
						String request = (String) CommUtils.deserializeBytes(msg.getMsg());

						// Handles the request
						response = handleRequest(request);

						// Encrypts and sends the response
						MsgSequence responseMsg = new MsgSequence(response.getBytes(), sequenceNumber);

						byte[] cypherTextAndHmac = EncryptionUtils.encryptAndHmac(CommUtils.serializeBytes(responseMsg), secretKey);

						out.write(cypherTextAndHmac);
						out.flush();

						return;
					}
					else {
						System.out.println("protocol_error\n");

						return;
					}
				}
			} catch (SocketTimeoutException e) {
				System.out.println("protocol_error");

				return;
			} catch (Exception e) {
				e.printStackTrace();
				return;
			}
		}

		private static synchronized String handleRequest(String request) {

			String[] parts = request.split(" ");
			if (parts.length < 2) return null;
			
			String command = parts[0];
			String account = parts[1];
			String returningString = "";
			
			switch (command) {
				case "CREATE":
					if (accounts.containsKey(account)) {
						returningString = null;
					} else {
						double initialBalance = Double.parseDouble(parts[2]);
						accounts.put(account, initialBalance);
						returningString = "{\"account\":\"" + account + "\", \"initial_balance\": " + initialBalance + "}";
						
					}

					if (returningString != null) {
						System.out.println("--------------------------------------------------");
						System.out.println(returningString);
						System.out.println("--------------------------------------------------\n");
					}

					return returningString;
				
				case "DEPOSIT":
					if (!accounts.containsKey(account)) {
						returningString = null;
					} else {
						double depositAmount = Double.parseDouble(parts[2]);
						if (depositAmount <= 0) {
							returningString = null;
						} else {
							accounts.put(account, accounts.get(account) + depositAmount);
						returningString = "{\"account\":\"" + account + "\", \"deposit\": " + depositAmount + "}";
						}
					}

					if (returningString != null) {
						System.out.println("--------------------------------------------------");
						System.out.println(returningString);
						System.out.println("--------------------------------------------------\n");
					}

					return returningString;
				
				case "WITHDRAW":
					if (!accounts.containsKey(account)) {
						returningString = null;
					} else {
						double withdrawAmount = Double.parseDouble(parts[2]);
						if (withdrawAmount > accounts.get(account)) {
							returningString = null;
						} else {
							accounts.put(account, accounts.get(account) - withdrawAmount);
							returningString = "{\"account\":\"" + account + "\", \"withdraw\": " + withdrawAmount + "}";
						}
					}

					if (returningString != null) {
						System.out.println("--------------------------------------------------");
						System.out.println(returningString);
						System.out.println("--------------------------------------------------\n");
					}

					return returningString;

				case "BALANCE":
					if (!accounts.containsKey(account)) {
						returningString = null;
					} else {
						returningString = "{\"account\":\"" + account + "\", \"balance\": " + accounts.get(account) + "}";
					}

					if (returningString != null) {
						System.out.println("--------------------------------------------------");
						System.out.println(returningString);
						System.out.println("--------------------------------------------------\n");
					}

					return returningString;

				default:
					returningString = null;
					return returningString;
			}
		}

		private SecretKey bankDH(PublicKey clientPublicKey) {
			try {
				KeyPairGenerator bankKp = KeyPairGenerator.getInstance("DH");
				bankKp.initialize(2048);
				KeyPair bankDHKeyPair = bankKp.generateKeyPair();

				//-------------- Bank envia chave publica DH ao atm
				byte[] bankDHPubKey = bankDHKeyPair.getPublic().getEncoded();
				
				//Criar chave AES para enviar DH Key
				KeyGenerator keyGen = KeyGenerator.getInstance("AES");
				keyGen.init(256);
				SecretKey aesKey = keyGen.generateKey();

				// Envia chave AES para o ATM
				byte[] rsaEncyptedAesKey = EncryptionUtils.rsaEncrypt(aesKey.getEncoded(), clientPublicKey);
				MsgSequence aesKeyMsg = new MsgSequence(rsaEncyptedAesKey, sequenceNumber);

				out.writeObject(aesKeyMsg);
				sequenceNumber++;

				//Envia DH pub key para o ATM
				byte[] dhKeyAesEncrypted = EncryptionUtils.encryptAndHmac(bankDHPubKey, aesKey);
				MsgSequence bankDHPubKeyMsg = new MsgSequence(dhKeyAesEncrypted, sequenceNumber);

				out.writeObject(bankDHPubKeyMsg);
				sequenceNumber++;
				
				// ----------------Envia hash signed da chave pub ao atm
				byte[] bankDHPubKeyHash = EncryptionUtils.hash(bankDHPubKey);
				byte[] bankDHPubKeyHashSigned = EncryptionUtils.sign(bankDHPubKeyHash, privateKey);
				MsgSequence bankDHPubKeyHashSignedMsg = new MsgSequence(bankDHPubKeyHashSigned, sequenceNumber);

				out.writeObject(bankDHPubKeyHashSignedMsg);
				sequenceNumber++;
				
				// -----------Receber chave publica DH do bank

				//Receber AES key do bank
				MsgSequence aesDHPubKeyMsg = (MsgSequence) in.readObject();

				if (aesDHPubKeyMsg.getSeqNumber() != sequenceNumber) {
					return null;
				}

				sequenceNumber++;

				byte[] atmAesDHPubKey = aesDHPubKeyMsg.getMsg();
				byte[] atmAesDHPubKeyDecoded = EncryptionUtils.rsaDecrypt(atmAesDHPubKey, privateKey);
				SecretKey aesKeyAtm = new SecretKeySpec(atmAesDHPubKeyDecoded, "AES");

				// Receber DH
				MsgSequence AtmDHPubKeyMsg = (MsgSequence) in.readObject();
				
				if (AtmDHPubKeyMsg.getSeqNumber() != sequenceNumber) {
					return null;
				}

				sequenceNumber++;

				byte[] atmDHPubKey = AtmDHPubKeyMsg.getMsg();
				byte[] atmDHPubKeyDecoded = EncryptionUtils.decryptAndVerifyHmac(atmDHPubKey, aesKeyAtm);

				// ---------- Hash da DH pub key do atm
				byte[] atmDHPubKeyHash = EncryptionUtils.hash(atmDHPubKeyDecoded);
				
				// ----------------------Recebe hash signed da DH pub key do atm
				MsgSequence atmDHPubKeyHashSignedMsg = (MsgSequence) in.readObject();

				if (atmDHPubKeyHashSignedMsg.getSeqNumber() != sequenceNumber) {
					return null;
				}

				sequenceNumber++;

				byte[] atmDHPubKeyHashSigned = atmDHPubKeyHashSignedMsg.getMsg();
				
				// -----------------------Verificar signature
				if (!EncryptionUtils.verifySignature(atmDHPubKeyHash, atmDHPubKeyHashSigned, clientPublicKey)) {
					return null;
				}
				
				SecretKey secretKey = EncryptionUtils.createSessionKey(bankDHKeyPair.getPrivate(), atmDHPubKeyDecoded);
				byte[] sessionKeyHash = EncryptionUtils.hash(secretKey.getEncoded());

				// --------------------Receber signed hash da session key do atm
				MsgSequence sessionKeyHashSignedMsg = (MsgSequence) in.readObject();

				if (sessionKeyHashSignedMsg.getSeqNumber() != sequenceNumber) {
					return null;
				}
	
				sequenceNumber++;

				// ----------------------Enviar signed hash da session key
				byte[] sessionKeyHashSigned = EncryptionUtils.sign(sessionKeyHash, privateKey);
				MsgSequence sessionKeyHashSignedMsgSend = new MsgSequence(sessionKeyHashSigned, sequenceNumber);

				out.writeObject(sessionKeyHashSignedMsgSend);
				sequenceNumber++;

				// ----------------Verificar a signature do atm na chave
				if (!EncryptionUtils.verifySignature(sessionKeyHash, sessionKeyHashSignedMsg.getMsg(), clientPublicKey)) {
					return null;
				}

				return secretKey;
			} catch (Exception e) {
				return null;
			}
		}

		public static ObjectOutputStream outputStream(Socket socket) {
			ObjectOutputStream outStream = null;

			try {
				outStream = new ObjectOutputStream(socket.getOutputStream());
			} catch (SocketTimeoutException e) {
				System.out.println("protocol_error");
			} catch (Exception e) {
				return null;
			}

			return outStream;
		}
		
		public static ObjectInputStream inputStream(Socket socket) {
			ObjectInputStream inStream = null;

			try {
				inStream = new ObjectInputStream(socket.getInputStream());
			} catch (SocketTimeoutException e) {
				System.out.println("protocol_error\n");
			} catch (Exception e) {
				return null;
			}
			return inStream;
		}
	}
}
