package com.ts_24_25;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.HashMap;

import javax.crypto.SecretKey;

public class BankThread  extends Thread {
    private Socket socket;
	private PrivateKey privateKey;
	private ObjectInputStream in;
	private ObjectOutputStream out;
    private static HashMap<String, Double> accounts = new HashMap<>();

    public BankThread(Socket socket, PrivateKey privateKey) {
		this.socket = socket;
		this.privateKey = privateKey;
	}

    public void run() {

        try {
            socket.setSoTimeout(10000);
            in = inputStream(socket);
            out = outputStream(socket);
            
            while (true) {
                String request = (String) in.readObject();
                String[] parts = request.split(" ");
        
                if (parts.length < 2) {
                    System.out.println("{\"error\":\"Invalid Request\"}");
                }
            
                String command = parts[0];
                String account = parts[1];
            
                switch (command) {
                    case "CREATE":
                        //Receber chave publica do cliente
                        byte[] clientPublicKeyBytes = (byte[]) in.readObject();
                        PublicKey clientPublicKey = (PublicKey) CommUtils.deserializeData(clientPublicKeyBytes);

                        //Mutual auth
						if (!bankAuthenticationChallenge(clientPublicKey)) {
                            System.exit(255);
                        }

                        //DH
                        SecretKey secretKey = bankDH(clientPublicKey);
						if (secretKey == null) {
                            System.exit(255);
                        }

                        if (accounts.containsKey(account)) {
                            System.out.println("{\"error\":\"Account Exists\"}");
                            return;
                        }
        
                        double initialBalance = Double.parseDouble(parts[2]);
                        accounts.put(account, initialBalance);
                        System.out.println("{\"account\":\"" + account + "\", \"initial_balance\": " + initialBalance + "}");
        
                        break;
                    
                    case "DEPOSIT":
                        if (!accounts.containsKey(account)) {
                            System.out.println("{\"error\":\"Account Not Found\"}");
                            return;
                        }
        
                        double depositAmount = Double.parseDouble(parts[2]);
                        if (depositAmount <= 0) {
                            System.out.println("{\"error\":\"Invalid Deposit Amount\"}");
                            return;
                        }
        
                        accounts.put(account, accounts.get(account) + depositAmount);
                        System.out.println("{\"account\":\"" + account + "\", \"deposit\": " + depositAmount + "}");
                        
                        break;
                    
                    case "WITHDRAW":
                        if (!accounts.containsKey(account)) {
                            System.out.println("{\"error\":\"Account Not Found\"}");
                            return;
                        }
        
                        double withdrawAmount = Double.parseDouble(parts[2]);
                        if (withdrawAmount > accounts.get(account)) {
                            System.out.println("{\"error\":\"Insufficient Funds\"}");
                            return;
                        }
        
                        accounts.put(account, accounts.get(account) - withdrawAmount);
                        System.out.println("{\"account\":\"" + account + "\", \"withdraw\": " + withdrawAmount + "}");
        
                        break;
                    
                    case "BALANCE":
                        if (!accounts.containsKey(account)) {
                            System.out.println("{\"error\":\"Account Not Found\"}");
                            return;
                        }
        
                        System.out.println("{\"account\":\"" + account + "\", \"balance\": " + accounts.get(account) + "}");

                        break;
        
                    default:
                        System.out.println("{\"error\":\"Unknown Command\"}");
                        break;
                }
            }
        } catch (SocketTimeoutException e) {
            System.out.println("protocol_error");
            System.exit(63);
        } catch (Exception e) {
            System.exit(255);
        }
    }

    private boolean bankAuthenticationChallenge(PublicKey clientPublicKey) {
		try {
			//Generate nonce and send it to client
			byte[] nonce = EncryptionUtils.generateNonce();
            byte[] encryptedNonceMessage = EncryptionUtils.rsaEncrypt(nonce, clientPublicKey);
			out.writeObject(encryptedNonceMessage);
			
			//Receive nonce back from client
			byte[] receivedNonce = (byte[]) in.readObject();
			
			//Check if client correctly decrypted nonce
			if (!Arrays.equals(nonce, receivedNonce)) {
				return false;
			}
			
			//Receiving nonce from client
			byte[] nonceEncrypted = (byte[]) in.readObject();
			byte[] nonceDecrypted = EncryptionUtils.rsaDecrypt(nonceEncrypted, privateKey); 
			
			byte[] encryptedBytes = EncryptionUtils.rsaEncrypt(nonceDecrypted, clientPublicKey);
			out.writeObject(encryptedBytes);
			
			return true;
		} catch (IOException | ClassNotFoundException e) {
			return false;
		}
	}

    private SecretKey bankDH(PublicKey clientPublicKey) {
        try {
        	KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
            keyPairGenerator.initialize(2048);
            KeyPair serverKeyPair = keyPairGenerator.generateKeyPair();
            
            //Send DH Public key to atm
            byte[] serverPublicKey = serverKeyPair.getPublic().getEncoded();
			out.writeObject(serverPublicKey);
			
			//Send a signed hash of the public key to confirm it is correct
	        byte[] dhPublicKeyHash = EncryptionUtils.createHash(serverPublicKey);
	        byte[] dhPublicKeyHashSigned = EncryptionUtils.sign(dhPublicKeyHash, privateKey);
	        out.writeObject(dhPublicKeyHashSigned);
	        
	        //Receive DH Public key from atm
			byte[] clientDHPublicKey = (byte[]) in.readObject();
			byte[] dhPubKeyHash = EncryptionUtils.createHash(clientDHPublicKey);
			
			//Receive signed hash of the client's DH public key
			byte[] clientDHPublicKeySignedHash = (byte[]) in.readObject();
			
			//Check if it matches the signature from the bank
			if (!EncryptionUtils.verifySignature(dhPubKeyHash, clientDHPublicKeySignedHash, clientPublicKey)) return null;
			
			SecretKey secretKey = EncryptionUtils.createSessionKey(serverKeyPair.getPrivate(), clientDHPublicKey);
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
			System.exit(63);
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
			System.exit(63);
        } catch (Exception e) {
			System.exit(255);
		}
        return inStream;
    }
}
