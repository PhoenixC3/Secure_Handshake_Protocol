package com.ts_24_25;

import java.io.*;
import java.net.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

import javax.crypto.SecretKey;

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
            System.out.println("Bank server is running on port " + port);

            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                try {
                    serverSocket.close();
                } catch (IOException e) {
                    System.exit(0);
                }

                System.exit(0);
            }));

            while (true) {
                Socket sock;

                try {
                    sock = serverSocket.accept();

                    BankThread bt = new BankThread(sock, privateKey);
                    bt.start();
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
				
				while (true) {
					//--------------Authentication----------------

					//Receber chave publica do cliente
					MsgSequence pubKeyMsgCreate = (MsgSequence) in.readObject();

					if (pubKeyMsgCreate.getSeqNumber() != sequenceNumber) {
					return;
					}

					sequenceNumber++;

					PublicKey clientPublicKeyCreate = (PublicKey) CommUtils.deserializeBytes(pubKeyMsgCreate.getMsg());

					//Mutual auth
					if (!bankNonceExchange(clientPublicKeyCreate)) {
						return;
					}

					//DH
					SecretKey secretKey = bankDH(clientPublicKeyCreate);
					if (secretKey == null) {
						return;
					}

					//--------------Authentication Finished----------------

					// Receives the request
					ArrayList<Byte> byteList = new ArrayList<>();
					do {
						byteList.add((byte) in.read());
					} while (in.available() != 0);

					byte[] allMessage = new byte[byteList.size()];
					for (int i = 0; i < byteList.size(); i++) {
						allMessage[i] = byteList.get(i);
					}

					// Decrypts the request
					byte[] decryptedMessage = EncryptionUtils.decryptAndVerifyHmac(allMessage, secretKey);

					// Converts the decrypted message to a string
					MsgSequence msg = null;
					try {
						msg = (MsgSequence) CommUtils.deserializeBytes(decryptedMessage);
					} catch (Exception e) {
						e.printStackTrace();
					}

					String response = null;
					if (msg == null) {
						System.exit(255);
					} else {
						// Verifies the sequence number
						if (msg.getSeqNumber() != sequenceNumber) {
							System.exit(255);
						}

						sequenceNumber++;
						
						String request = new String(msg.getMsg());

						// Handles the request
						response = handleRequest(request);
					}

					// Encrypts and sends the response
					MsgSequence responseMsg = new MsgSequence(response.getBytes(), sequenceNumber);

					byte[] cypherTextAndHmac = EncryptionUtils.encryptAndHmac(CommUtils.serializeBytes(responseMsg), secretKey);

					out.write(cypherTextAndHmac);
					out.flush();
				}
			} catch (SocketTimeoutException e) {
				System.out.println("protocol_error");
			} catch (Exception e) {
				System.exit(255);
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
						System.out.println(returningString + "\n");
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
						System.out.println(returningString + "\n");
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
						System.out.println(returningString + "\n");
					}

					return returningString;

				case "BALANCE":
					if (!accounts.containsKey(account)) {
						returningString = null;
					} else {
						returningString = "{\"account\":\"" + account + "\", \"balance\": " + accounts.get(account) + "}";
					}

					if (returningString != null) {
						System.out.println(returningString + "\n");
					}

					return returningString;

				default:
					returningString = null;
					return returningString;
			}
		}

		private boolean bankNonceExchange(PublicKey clientPubKey) {
			try {
				//------- CLIENT AUTH

				// Enviar nonce para o atm
				byte[] nonce = EncryptionUtils.generateNonce();
				MsgSequence nonceMsg = new MsgSequence(nonce, sequenceNumber);
				byte[] encryptedNonceMessage = EncryptionUtils.rsaEncrypt(CommUtils.serializeBytes(nonceMsg), clientPubKey);

				out.writeObject(encryptedNonceMessage);
				sequenceNumber++;
				
				// Receber nonce do atm
				byte[] nonceEncrypted = (byte[]) in.readObject();
				byte[] nonceDecrypted = EncryptionUtils.rsaDecrypt(nonceEncrypted, privateKey);
				MsgSequence nonceDecryptedMsg = (MsgSequence) CommUtils.deserializeBytes(nonceDecrypted);

				if (nonceDecryptedMsg.getSeqNumber() != sequenceNumber) {
					return false;
				}

				sequenceNumber++;
				
				// Verificar decrypt do atm
				if (!Arrays.equals(nonce, nonceDecryptedMsg.getMsg())) {
					MsgSequence challengeResult = new MsgSequence(CommUtils.serializeBytes("CHALLENGE_FAILED"), sequenceNumber);
					out.writeObject(challengeResult);

					return false;
				}

				MsgSequence challengeResult = new MsgSequence(CommUtils.serializeBytes("CHALLENGE_PASSED"), sequenceNumber);
				out.writeObject(challengeResult);

				sequenceNumber++;
				
				//------- BANK AUTH
				
				// Receber nonce do atm e decrypt
				byte[] nonceEncryptedMine = (byte[]) in.readObject();
				byte[] nonceDecryptedMine = EncryptionUtils.rsaDecrypt(nonceEncryptedMine, privateKey);
				MsgSequence nonceDecryptedMsgMine = (MsgSequence) CommUtils.deserializeBytes(nonceDecryptedMine);

				if (nonceDecryptedMsgMine.getSeqNumber() != sequenceNumber) {
					return false;
				}

				sequenceNumber++;
				
				// Encrypt e reenviar para o atm
				MsgSequence nonceToSend = new MsgSequence(nonceDecryptedMsg.getMsg(), sequenceNumber);
				byte[] encryptedBytes = EncryptionUtils.rsaEncrypt(CommUtils.serializeBytes(nonceToSend), clientPubKey);

				out.writeObject(encryptedBytes);
				sequenceNumber++;
				
				//Resposta do atm
				MsgSequence challengeResultMine = (MsgSequence) in.readObject();
				String result = (String) CommUtils.deserializeBytes(challengeResultMine.getMsg());
				
				if (challengeResultMine.getSeqNumber() != sequenceNumber || result.equals("CHALLENGE_FAILED")) {
					return false;
				}
				
				sequenceNumber++;
				
				return true;
			} catch (IOException | ClassNotFoundException e) {
				return false;
			}
		}

		private SecretKey bankDH(PublicKey clientPublicKey) {
			try {
				KeyPairGenerator bankKp = KeyPairGenerator.getInstance("DH");
				bankKp.initialize(2048);
				KeyPair bankDHKeyPair = bankKp.generateKeyPair();
				
				// Bank envia chave publica DH ao atm
				byte[] bankDHPubKey = bankDHKeyPair.getPublic().getEncoded();
				MsgSequence bankDHPubKeyMsg = new MsgSequence(bankDHPubKey, sequenceNumber);
				out.writeObject(bankDHPubKeyMsg);
				sequenceNumber++;
				
				//Send a signed hash of the public key to confirm it is correct
				byte[] bankDHPubKeyHash = EncryptionUtils.hash(bankDHPubKey);
				byte[] bankDHPubKeyHashSigned = EncryptionUtils.sign(bankDHPubKeyHash, privateKey);
				MsgSequence bankDHPubKeyHashSignedMsg = new MsgSequence(bankDHPubKeyHashSigned, sequenceNumber);
				out.writeObject(bankDHPubKeyHashSignedMsg);
				sequenceNumber++;
				
				// Receber DH pub key do ATM
				MsgSequence atmDHPubKeyMsg = (MsgSequence) in.readObject();

				if (atmDHPubKeyMsg.getSeqNumber() != sequenceNumber) {
					return null;
				}

				sequenceNumber++;

				byte[] atmDHPubKey = atmDHPubKeyMsg.getMsg();
				byte[] atmDHPubKeyHash = EncryptionUtils.hash(atmDHPubKey);
				
				// Recebe hash signed da chave pub do atm
				MsgSequence atmDHPubKeyHashSignedMsg = (MsgSequence) in.readObject();

				if (atmDHPubKeyHashSignedMsg.getSeqNumber() != sequenceNumber) {
					return null;
				}

				sequenceNumber++;

				byte[] atmDHPubKeyHashSigned = atmDHPubKeyHashSignedMsg.getMsg();
				
				//Check if it matches the signature from the bank
				if (!EncryptionUtils.verifySignature(atmDHPubKeyHash, atmDHPubKeyHashSigned, clientPublicKey)) {
					return null;
				}
				
				SecretKey secretKey = EncryptionUtils.createSessionKey(bankDHKeyPair.getPrivate(), atmDHPubKey);
				return secretKey;
			} catch (IOException | ClassNotFoundException | NoSuchAlgorithmException e) {
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
				System.exit(255);
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
				System.exit(255);
			}
			return inStream;
		}
	}
}
