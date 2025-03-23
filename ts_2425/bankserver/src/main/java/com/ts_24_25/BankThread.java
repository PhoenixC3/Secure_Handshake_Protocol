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
    private int messageCounter;

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
                //Receber o tipo de request do atm
                byte[] recBytes = (byte[]) in.readObject();

                //Desencriptar a mensagem
                byte[] decRec = EncryptionUtils.rsaDecrypt(recBytes, privateKey);

                //Deserialize da mensagem
                MsgSequence decMsg = (MsgSequence) CommUtils.deserializeBytes(decRec);

                //Counter
                messageCounter = decMsg.getSeqNumber();
                messageCounter++;

                CommandType command = (CommandType) CommUtils.deserializeBytes(decMsg.getMsg());
            
                switch (command) {
                    case CommandType.CREATE:
                        //Receber chave publica do cliente
                        MsgSequence pubKeyMsgCreate = (MsgSequence) in.readObject();

						if (pubKeyMsgCreate.getSeqNumber() != messageCounter) {
                           return;
                        }

						messageCounter++;

						PublicKey clientPublicKeyCreate = (PublicKey) CommUtils.deserializeBytes(pubKeyMsgCreate.getMsg());

                        //Mutual auth
						if (!bankAuthenticationChallenge(clientPublicKeyCreate)) {
                            return;
                        }

                        //DH
                        SecretKey secretKeyCreate = bankDH(clientPublicKeyCreate);
						if (secretKeyCreate == null) {
                            return;
                        }

                        // String account = "banana";
                        // if (accounts.containsKey(account)) {
                        //     System.out.println("{\"error\":\"Account Exists\"}");
                        //     return;
                        // }
        
                        // double initialBalance = Double.parseDouble(account);
                        // accounts.put(account, initialBalance);
                        // System.out.println("{\"account\":\"" + account + "\", \"initial_balance\": " + initialBalance + "}");
        
                        break;
                    
                    case CommandType.DEPOSIT:
                        //Receber chave publica do cliente
                        MsgSequence pubKeyMsgDeposit = (MsgSequence) in.readObject();

                        if (pubKeyMsgDeposit.getSeqNumber() != messageCounter) {
                        return;
                        }

                        messageCounter++;

                        PublicKey clientPublicKeyDeposit = (PublicKey) CommUtils.deserializeBytes(pubKeyMsgDeposit.getMsg());

                        //Mutual auth
                        if (!bankAuthenticationChallenge(clientPublicKeyDeposit)) {
                            return;
                        }

                        //DH
                        SecretKey secretKeyDeposit = bankDH(clientPublicKeyDeposit);
                        if (secretKeyDeposit == null) {
                            return;
                        }

                    //     if (!accounts.containsKey(account)) {
                    //         System.out.println("{\"error\":\"Account Not Found\"}");
                    //         return;
                    //     }
        
                    //     double depositAmount = Double.parseDouble(parts[2]);
                    //     if (depositAmount <= 0) {
                    //         System.out.println("{\"error\":\"Invalid Deposit Amount\"}");
                    //         return;
                    //     }
        
                    //     accounts.put(account, accounts.get(account) + depositAmount);
                    //     System.out.println("{\"account\":\"" + account + "\", \"deposit\": " + depositAmount + "}");
                        
                        break;
                    
                    case CommandType.WITHDRAW:
                        //Receber chave publica do cliente
                        MsgSequence pubKeyMsgWithdraw = (MsgSequence) in.readObject();

                        if (pubKeyMsgWithdraw.getSeqNumber() != messageCounter) {
                        return;
                        }

                        messageCounter++;

                        PublicKey clientPublicKeyWithdraw = (PublicKey) CommUtils.deserializeBytes(pubKeyMsgWithdraw.getMsg());

                        //Mutual auth
                        if (!bankAuthenticationChallenge(clientPublicKeyWithdraw)) {
                            return;
                        }

                        //DH
                        SecretKey secretKeyWithdraw = bankDH(clientPublicKeyWithdraw);
                        if (secretKeyWithdraw == null) {
                            return;
                        }

                    //     if (!accounts.containsKey(account)) {
                    //         System.out.println("{\"error\":\"Account Not Found\"}");
                    //         return;
                    //     }
        
                    //     double withdrawAmount = Double.parseDouble(parts[2]);
                    //     if (withdrawAmount > accounts.get(account)) {
                    //         System.out.println("{\"error\":\"Insufficient Funds\"}");
                    //         return;
                    //     }
        
                    //     accounts.put(account, accounts.get(account) - withdrawAmount);
                    //     System.out.println("{\"account\":\"" + account + "\", \"withdraw\": " + withdrawAmount + "}");
        
                        break;
                    
                    case CommandType.BALANCE:
                        //Receber chave publica do cliente
                        MsgSequence pubKeyMsgBalance = (MsgSequence) in.readObject();

                        if (pubKeyMsgBalance.getSeqNumber() != messageCounter) {
                        return;
                        }

                        messageCounter++;

                        PublicKey clientPublicKeyBalance = (PublicKey) CommUtils.deserializeBytes(pubKeyMsgBalance.getMsg());

                        //Mutual auth
                        if (!bankAuthenticationChallenge(clientPublicKeyBalance)) {
                            return;
                        }

                        //DH
                        SecretKey secretKeyBalance = bankDH(clientPublicKeyBalance);
                        if (secretKeyBalance == null) {
                            return;
                        }

                    //     if (!accounts.containsKey(account)) {
                    //         System.out.println("{\"error\":\"Account Not Found\"}");
                    //         return;
                    //     }
        
                    //     System.out.println("{\"account\":\"" + account + "\", \"balance\": " + accounts.get(account) + "}");

                        break;
        
                    default:
                        System.out.println("{\"error\":\"Unknown Command\"}");

                        break;
                }
            }
        } catch (SocketTimeoutException e) {
            System.out.println("protocol_error");
        } catch (Exception e) {
            System.exit(255);
        }
    }

    private boolean bankAuthenticationChallenge(PublicKey clientPubKey) {
		try {
            //------- CLIENT AUTH

			// Enviar nonce para o atm
			byte[] nonce = EncryptionUtils.generateNonce();
            MsgSequence nonceMsg = new MsgSequence(nonce, messageCounter);
            byte[] encryptedNonceMessage = EncryptionUtils.rsaEncrypt(CommUtils.serializeBytes(nonceMsg), clientPubKey);

			out.writeObject(encryptedNonceMessage);
            messageCounter++;
			
			// Receber nonce do atm
            byte[] nonceEncrypted = (byte[]) in.readObject();
			byte[] nonceDecrypted = EncryptionUtils.rsaDecrypt(nonceEncrypted, privateKey);
			MsgSequence nonceDecryptedMsg = (MsgSequence) CommUtils.deserializeBytes(nonceDecrypted);

			if (nonceDecryptedMsg.getSeqNumber() != messageCounter) {
				return false;
			}

			messageCounter++;
			
			// Verificar decrypt do atm
			if (!Arrays.equals(nonce, nonceDecryptedMsg.getMsg())) {
				MsgSequence challengeResult = new MsgSequence(CommUtils.serializeBytes("CHALLENGE_FAILED"), messageCounter);
				out.writeObject(challengeResult);

				return false;
			}

			MsgSequence challengeResult = new MsgSequence(CommUtils.serializeBytes("CHALLENGE_PASSED"), messageCounter);
			out.writeObject(challengeResult);

			messageCounter++;
            
            //------- BANK AUTH
			
			// Receber nonce do atm e decrypt
			byte[] nonceEncryptedMine = (byte[]) in.readObject();
			byte[] nonceDecryptedMine = EncryptionUtils.rsaDecrypt(nonceEncryptedMine, privateKey);
			MsgSequence nonceDecryptedMsgMine = (MsgSequence) CommUtils.deserializeBytes(nonceDecryptedMine);

			if (nonceDecryptedMsg.getSeqNumber() != messageCounter) {
				return false;
			}

			messageCounter++;
			
			// Encrypt e reenviar para o atm
			MsgSequence nonceToSend = new MsgSequence(nonceDecryptedMsg.getMsg(), messageCounter);
			byte[] encryptedBytes = EncryptionUtils.rsaEncrypt(CommUtils.serializeBytes(nonceToSend), clientPubKey);

			out.writeObject(encryptedBytes);
			messageCounter++;
			
			//Resposta do atm
			MsgSequence challengeResultMine = (MsgSequence) in.readObject();
			String result = (String) CommUtils.deserializeBytes(challengeResultMine.getMsg());
			
			if (challengeResultMine.getSeqNumber() != messageCounter || result.equals("CHALLENGE_FAILED")) {
				return false;
			}
			
			messageCounter++;
			
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
            MsgSequence bankDHPubKeyMsg = new MsgSequence(bankDHPubKey, messageCounter);
			out.writeObject(bankDHPubKeyMsg);
			messageCounter++;
			
			//Send a signed hash of the public key to confirm it is correct
	        byte[] bankDHPubKeyHash = EncryptionUtils.hash(bankDHPubKey);
	        byte[] bankDHPubKeyHashSigned = EncryptionUtils.sign(bankDHPubKeyHash, privateKey);
	        MsgSequence bankDHPubKeyHashSignedMsg = new MsgSequence(bankDHPubKeyHashSigned, messageCounter);
	        out.writeObject(bankDHPubKeyHashSignedMsg);
	        messageCounter++;
	        
	        // Receber DH pub key do ATM
			MsgSequence atmDHPubKeyMsg = (MsgSequence) in.readObject();

			if (atmDHPubKeyMsg.getSeqNumber() != messageCounter) {
                return null;
            }

			messageCounter++;

			byte[] atmDHPubKey = atmDHPubKeyMsg.getMsg();
			byte[] atmDHPubKeyHash = EncryptionUtils.hash(atmDHPubKey);
			
			// Recebe hash signed da chave pub do atm
			MsgSequence atmDHPubKeyHashSignedMsg = (MsgSequence) in.readObject();

			if (atmDHPubKeyHashSignedMsg.getSeqNumber() != messageCounter) {
                return null;
            }

			messageCounter++;

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
