package com.ts_24_25;

import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

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
			
			if(flag.equals("-s")) {
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
		} catch (IOException e) {
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

                    BankThread newServerThread = new BankThread(sock, privateKey);
                    newServerThread.start();
                } catch (IOException e) {
                    System.out.println("protocol_error");
                    System.exit(63);
                }
            }
        } catch (IOException e) {
            System.out.println("protocol_error");
            System.exit(63);
        }
    }
}
