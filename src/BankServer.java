package src;
// BankServer.java
import java.io.*;
import java.net.*;
import java.util.*;

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
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-p":
                    if (i + 1 >= args.length) return false;
                    try {
                        port = Integer.parseInt(args[++i]);
                    } catch (NumberFormatException e) {
                        return false;
                    }
                    break;
                case "-s":
                    if (i + 1 >= args.length) return false;
                    authFile = args[++i];
                    break;
                default:
                    return false;
            }
        }
        return true;
    }

    private void createAuthFile() {
        File file = new File(authFile);
        if (file.exists()) {
            System.exit(255);
        }
        try (FileWriter writer = new FileWriter(file)) {
            writer.write("Banana\n");
            System.out.println("created");
        } catch (IOException e) {
            System.exit(255);
        }
    }

    public void start() {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Bank server is running on port " + port);
            while (true) {
                new ClientHandler(serverSocket.accept()).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static class ClientHandler extends Thread {
        private Socket socket;

        public ClientHandler(Socket socket) {
            this.socket = socket;
        }

        public void run() {
            try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                 PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {

                String request = in.readLine();
                String response = handleRequest(request);
                out.println(response);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private static synchronized String handleRequest(String request) {

        String[] parts = request.split(" ");
        if (parts.length < 2) return "{\"error\":\"Invalid Request\"}";
        
        String command = parts[0];
        String account = parts[1];
        
        switch (command) {
            case "CREATE":
                if (accounts.containsKey(account)) return "{\"error\":\"Account Exists\"}";
                double initialBalance = Double.parseDouble(parts[2]);
                accounts.put(account, initialBalance);
                return "{\"account\":\"" + account + "\", \"initial_balance\": " + initialBalance + "}";
            
            case "DEPOSIT":
                if (!accounts.containsKey(account)) return "{\"error\":\"Account Not Found\"}";
                double depositAmount = Double.parseDouble(parts[2]);
                if (depositAmount <= 0) return "{\"error\":\"Invalid Deposit Amount\"}";
                accounts.put(account, accounts.get(account) + depositAmount);
                return "{\"account\":\"" + account + "\", \"deposit\": " + depositAmount + "}";
            
            case "WITHDRAW":
                if (!accounts.containsKey(account)) return "{\"error\":\"Account Not Found\"}";
                double withdrawAmount = Double.parseDouble(parts[2]);
                if (withdrawAmount > accounts.get(account)) return "{\"error\":\"Insufficient Funds\"}";
                accounts.put(account, accounts.get(account) - withdrawAmount);
                return "{\"account\":\"" + account + "\", \"withdraw\": " + withdrawAmount + "}";
            
            case "BALANCE":
                if (!accounts.containsKey(account)) return "{\"error\":\"Account Not Found\"}";
                return "{\"account\":\"" + account + "\", \"balance\": " + accounts.get(account) + "}";

            default:
                return "{\"error\":\"Unknown Command\"}";
        }
    }
}
