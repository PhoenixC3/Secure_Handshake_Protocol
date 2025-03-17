import java.io.*;
import java.net.*;

public class ATMClient {
    private String ip = "127.0.0.1";
    private int port = 3000;
    private String authFile = "bank.auth";
    private String cardFile;
    private String account;
    private String command;
    private String amount;

    public ATMClient(String[] args) {
        if (!parseArguments(args)) {
            System.exit(255);
        }
    }

    private boolean parseArguments(String[] args) {
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-s": authFile = args[++i]; break;
                case "-i": ip = args[++i]; break;
                case "-p": port = Integer.parseInt(args[++i]); break;
                case "-c": cardFile = args[++i]; break;
                case "-a": account = args[++i]; break;
                case "-n": case "-d": case "-w": case "-g":
                    command = args[i];
                    if (!command.equals("-g")) amount = args[++i];
                    break;
                default: return false;
            }
        }
        return account != null && command != null;
    }

    public void execute() {
        try (Socket socket = new Socket(ip, port);
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
