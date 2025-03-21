package com.ts_24_25;
import java.io.*;
import java.net.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import javax.crypto.SecretKey;

public class ATMClient {
    private String ip;
    private String port;
    private String authFile;
    private String cardFile;
    private String account;
    private String command;
    private String amount;
	private PrivateKey privateKey;

	public static void main(String[] args) {
        ATMClient client = new ATMClient(args);
        client.execute();
    }

    public ATMClient(String[] args) {
        // -a account
        if (args.length < 2) {
			System.exit(255);
		}

        parseArgs(args);

        //Verificar sintaxe dos argumentos (Regex)
        if (!VerifyArgs.verifyAccountName(account)) 
			System.exit(255);
		
		if (authFile != null && !VerifyArgs.verifyFileNames(authFile)) {
			System.exit(255);
		}
		
		if (cardFile != null && !VerifyArgs.verifyFileNames(cardFile)) {
			System.exit(255);
		}
		
		if (amount != null && !VerifyArgs.verifyAmount(amount)) {
			System.exit(255);
		}
		
		if (port != null && !VerifyArgs.verifyPort(port)) {
			System.exit(255);
		}
		
		if (ip == null) {
			ip = "127.0.0.1";
		}
		
		if (authFile == null) {
			authFile = "bank.auth";
		}
		
		if (cardFile == null) {
            cardFile = account + ".card";
		}
		
		if (!VerifyArgs.verifyIPAddress(ip)) 
			System.exit(255);
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
			
			if(flag.equals("-a")) {
				if (account != null) {
					System.exit(255);
				}
				if (value == null && i + 1 < args.length) {
					account = args[i + 1];
					i++;
				}
				else if (i + 1 >= args.length && value == null) {
					System.exit(255);
				}
				else {
					account = value;
				}
			}
			else if(flag.equals("-s")) {
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
			else if(flag.equals("-i")) {
				if (ip != null) {
					System.exit(255);
				}
				if (value == null && i + 1 < args.length) {
					ip = args[i+1];
					i++;
				}
				else if (i + 1 >= args.length && value == null) {
					System.exit(255);
				}
				else {
					ip = value;
				}
			}
			else if(flag.equals("-p")) {
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
			else if(flag.equals("-c")) {
				if (cardFile != null) {
					System.exit(255);
				}
				if (value == null && i + 1 < args.length) {
					cardFile = args[i + 1];
					i++;
				}
				else if (i + 1 >= args.length && value == null) {
					System.exit(255);
				}
				else {
					cardFile = value;
				}
			}
			else if(flag.equals("-n")) {
				
				if (command != null) {
					System.exit(255);
				}

				command = "-n";
                
				if (value == null && i + 1 < args.length) {
					amount = args[i + 1];
					i++;
				}
				else if (i + 1 >= args.length && value == null) {
					System.exit(255);
				}
				else {
					amount = value;
				}
			}
			else if(flag.equals("-d")) {
				if (command != null) {
					System.exit(255);
				}

				command = "-d";

				if (value == null && i + 1 < args.length) {
					amount = args[i + 1];
					i++;
				}
				else if (i + 1 >= args.length && value == null) {
					System.exit(255);
				}
				else {
					amount = value;
				}
			}
			else if(flag.equals("-w")) {
				if (command != null) {
					System.exit(255);
				}

				command = "-w";

				if (value == null && i + 1 < args.length) {
					amount = args[i + 1];
					i++;
				}
				else if (i + 1 >= args.length && value == null) {
					System.exit(255);
				}
				else {
					amount = value;
				}
			}
			else if(flag.equals("-g")) {
				if (command != null) {
					System.exit(255);
				}

				command = "-g";
			}
			
			i++;
		}
		
		if(account == null) {
			System.exit(255);
		} 
		if(command == null) {
			System.exit(255);
		}
	}

    public void execute() {
        int bankPort;
		try {
			bankPort = Integer.parseInt(port);
		} catch (NumberFormatException e) {
			bankPort = 3000;
		}

		PublicKey authBank = getAuthBankFromFile(authFile);

        try (Socket socket = new Socket(ip, bankPort);
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {
    
            String formattedCommand = switch (command) {
                case "-n" -> "CREATE";
                case "-d" -> "DEPOSIT";
                case "-w" -> "WITHDRAW";
                case "-g" -> "BALANCE";
                default -> "";
            };

            if (formattedCommand.isEmpty()) {
                System.exit(255);
            }

			switch (formattedCommand) {
				case "CREATE":
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

					//Criar card file

					//-------------------Autenticacao mutua (FALTA sequence numbers)

					//Troca de nonce
					clientAuthenticationChallenge(in, out, authBank, privateKey);

					//Diffie Hellman
					SecretKey secretKey = clientDH(in, out, authBank, privateKey);

					//-------------------Fim de autenticacao mutua

					//Enviar msg
					ClientRequestMsg msg = new ClientRequestMsg(CommandType.CREATE, account, cardFile, amount);
					//Depois vai ser encriptada com a chave secreta DH e enviada

					break;
			
				default:
					break;
			}
        } catch (IOException e) {
            System.exit(255);
        }
    }

	private static PublicKey getAuthBankFromFile(String authFileName) {
		PublicKey publicKey = null;

		try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(authFileName))) {
			publicKey = (PublicKey) ois.readObject();
		} catch (Exception e) {
			System.exit(255);
		}

		return publicKey;
	}

	private boolean clientAuthenticationChallenge(ObjectInputStream inFromServer, ObjectOutputStream outToServer, PublicKey bankPublicKey, PrivateKey privateKey) {
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

	private SecretKey clientDH(ObjectInputStream in, ObjectOutputStream out, PublicKey authBank, PrivateKey privateKey) {
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
