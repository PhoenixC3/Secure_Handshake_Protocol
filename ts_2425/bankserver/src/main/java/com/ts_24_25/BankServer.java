package com.ts_24_25;

// BankServer.java
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class BankServer {
    private int port = 3000;
    private String authFile = "bank.auth";
    private static HashMap<String, Double> accounts = new HashMap<>();

    public static void main(String[] args) {
        BankServer server = new BankServer(args);
        server.start();
    }

    public BankServer(String[] args) {
        if (!parseArguments(args)) {
            System.exit(255);
        }
        createAuthFile();
    }

    private boolean parseArguments(String[] args) {
        if (args.length > 4096) return false;
    
        Set<String> seenArgs = new HashSet<>();
        String prevFlag = null;
    
        for (String arg : args) {
            arg = arg.trim();
    
            if (arg.isEmpty()) continue;
    
            if (arg.startsWith("-")) {

                if (seenArgs.contains(arg)) return false;
    
                seenArgs.add(arg);
                prevFlag = arg;
            } else {
                if (prevFlag == null) return false;
    
                if (prevFlag.equals("-p")) {
                    if (!VerifyArgs.verifyPort(arg)) return false;
                    port = Integer.parseInt(arg);
                } else if (prevFlag.equals("-s")) {
                    if (!VerifyArgs.verifyFileNames(arg)) return false;
                    authFile = arg;
                }
    
                prevFlag = null;
            }
        }
        if (prevFlag != null) return false;
        return true;
    }
    
    private void createAuthFile() {
        File file = new File(authFile);
        if (file.exists()) {
            System.exit(255);
        }
        try (FileWriter writer = new FileWriter(file)) {
            writer.write("Banana\n"); // Remove this line later
            System.out.println("created");
        } catch (IOException e) {
            System.exit(255);
        }
    }

    public void start() {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            while (true) {
                new ClientHandler(serverSocket.accept()).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static class ClientHandler extends Thread {

        private int seqNumber = 0;
        private Socket socket;

        public ClientHandler(Socket socket) {
            this.socket = socket;
        }

        public void run() {
            try (InputStream in = socket.getInputStream();
                    OutputStream out = socket.getOutputStream();) {

                // Set socket timeout to 10 seconds (10000 milliseconds)
                socket.setSoTimeout(10000);

                // MUDAR A PARTIR DAQUI PARA GERAR A SECRET KEY A PARTIR DO DIFFIE-HELLMAN

                // Recebe o tamanho da chave
                int keyLength = in.read();
                if (keyLength <= 0) {
                    throw new IOException("Invalid key length received");
                }

                // Lê a chave em bytes
                byte[] keyBytes = new byte[keyLength];
                int bytesRead = in.read(keyBytes);
                if (bytesRead != keyLength) {
                    throw new IOException("Incomplete key received");
                }

                // Converte os bytes de volta para uma chave AES
                SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

                // MUDAR A PARTE DE CIMA

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
                    msg = MsgSequence.fromBytes(decryptedMessage);
                } catch (ClassNotFoundException e) {
                    e.printStackTrace();
                }

                String response = null;
                if (msg == null) {
                    System.exit(255);
                } else {
                    // Verifies the sequence number
                    if (msg.getSeqNumber() != seqNumber) {
                        System.exit(255);
                    }
                    seqNumber++;
                    String request = new String(msg.getMsg());

                    // Handles the request
                    response = handleRequest(request);
                }

                // Encrypts and sends the response
                MsgSequence responseMsg = new MsgSequence(response.getBytes(), seqNumber);

                byte[] cypherTextAndHmac = EncryptionUtils.encryptAndHmac(responseMsg.toBytes(), secretKey);

                out.write(cypherTextAndHmac);
                out.flush();

            } catch (SocketTimeoutException e) {
                System.out.println("protocol_error");
            } catch (IOException e) {
                e.printStackTrace();
            }
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
}
