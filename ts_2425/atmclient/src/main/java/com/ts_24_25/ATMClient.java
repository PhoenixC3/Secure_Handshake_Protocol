package com.ts_24_25;
import java.io.*;
import java.net.*;

public class ATMClient {
    private String ip;
    private String port;
    private String authFile;
    private String cardFile;
    private String account;
    private String command;
    private String amount;

    public ATMClient(String[] args) {
        // -a account
        if (args.length < 2) {
			System.exit(255);
		}

        parseArgs(args);

        //Verificar sintaxe dos argumentos (Regex)
        if (!VerifyArgs.verifyAccountName(account)) 
			System.exit(255);
		
		if (authFile != null && !VerifyArgs.verifyFileNames(authFile)) 
			System.exit(255);
		
		if (cardFile != null && !VerifyArgs.verifyFileNames(cardFile)) 
			System.exit(255);	
		
		if (amount != null && !VerifyArgs.verifyAmount(amount)) 
			System.exit(255);
		
		if (port != null && !VerifyArgs.verifyPort(port)) 
			System.exit(255);
		
		
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

        try (Socket socket = new Socket(ip, bankPort);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
    
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

            out.println(formattedCommand + " " + account + (amount != null ? " " + amount : ""));
            System.out.println(in.readLine());
        } catch (IOException e) {
            System.exit(255);
        }
    }

    public static void main(String[] args) {
        ATMClient client = new ATMClient(args);
        client.execute();
    }
}
