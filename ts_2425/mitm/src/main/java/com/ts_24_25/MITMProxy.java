package ts_2425.mitm.src.main.java.com.ts_24_25;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class MITMProxy {
    private static int mitmPort = 4000;
    private static String bankIP = "127.0.0.1"; 
    private static int bankPort = 3000;
    private static final List<String> messageHistory = new ArrayList<>();
    private static ServerSocket serverSocket; // Global socket for SIGTERM handling
    private static boolean running = true; // Control flag for clean shutdown

    public static void main(String[] args) {
        parseArguments(args);

        // Set up SIGTERM handling
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\n[!] SIGTERM received. Shutting down MITM Proxy...");
            shutdown(running, serverSocket);
        }));

        try (ServerSocket serverSocket = new ServerSocket(mitmPort)) {
            System.out.println("MITM Proxy listening on port " + mitmPort);

            while (true) {
                Socket atmSocket = serverSocket.accept();
                System.out.println("Connected to ATM: " + atmSocket.getInetAddress());

                Socket bankSocket = new Socket(bankIP, bankPort);
                System.out.println("Connected to Bank: " + bankIP + ":" + bankPort);

                // Start bidirectional proxy with user-controlled message handling
                new Thread(new ProxyThread(atmSocket, bankSocket, "ATM -> Bank")).start();
                new Thread(new ProxyThread(bankSocket, atmSocket, "Bank -> ATM")).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void parseArguments(String[] args) {
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-p":
                    mitmPort = Integer.parseInt(args[++i]);
                    break;
                case "-s":
                    bankIP = args[++i];
                    break;
                case "-q":
                    bankPort = Integer.parseInt(args[++i]);
                    break;
                default:
                    System.out.println("Invalid argument: " + args[i]);
                    System.exit(255);
            }
        }
    }

    private static void shutdown(boolean running, ServerSocket serverSocket) {
        running = false;
        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
                System.out.println("MITM Proxy has shut down cleanly.");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Relay the data between the ATM and Bank
    static class ProxyThread implements Runnable {
        private Socket inputSocket;
        private Socket outputSocket;
        private final String direction; // "ATM -> Bank" or "Bank -> ATM"

        public ProxyThread(Socket inputSocket, Socket outputSocket, String direction) {
            this.inputSocket = inputSocket;
            this.outputSocket = outputSocket;
            this.direction = direction;
        }

        @Override
        public void run() {
            try {

                InputStream inputStream = inputSocket.getInputStream();
                OutputStream outputStream = outputSocket.getOutputStream();
                InputStream outputStreamFromServer = outputSocket.getInputStream();
                OutputStream inputStreamToServer = inputSocket.getOutputStream();

                Thread inputThread = new Thread(() -> forwardData(inputStream, outputStream));
                Thread outputThread = new Thread(() -> forwardData(outputStreamFromServer, inputStreamToServer));
                inputThread.start();
                outputThread.start();
                inputThread.join();
                outputThread.join();
            } catch (IOException | InterruptedException e) {
                e.printStackTrace();
            }
        }

        // Forward data between input and output
        private void forwardData(InputStream in, OutputStream out) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            Scanner scanner = new Scanner(System.in);

            try {
                while ((bytesRead = in.read(buffer)) != -1) {
                    String interceptedMessage = new String(buffer, 0, bytesRead);
                    messageHistory.add(interceptedMessage); // Store message for replaying
                    System.out.println("Intercepted [" + this.direction + "]: " + interceptedMessage);

                    System.out.println("Choose an action:");
                    System.out.println("1) Forward message unchanged");
                    System.out.println("2) Modify message");
                    System.out.println("3) Drop message");
                    System.out.println("4) Inject new message");
                    System.out.print("Enter choice (1-4): ");
                    int choice = scanner.nextInt();
                    scanner.nextLine();

                    switch (choice) {
                        case 1: // Forward message unchanged
                            out.write(buffer, 0, bytesRead);
                            out.flush();
                            break;

                        case 2: // Modify message
                            System.out.print("Enter modified message: ");
                            String modifiedMessage = scanner.nextLine();
                            out.write(modifiedMessage.getBytes());
                            out.flush();
                            break;

                        case 3: // Drop message
                            System.out.println("Message dropped.");
                            break;

                        case 4: // Inject new message
                            System.out.print("Enter new message to send: ");
                            String newMessage = scanner.nextLine();
                            out.write(newMessage.getBytes());
                            out.flush();
                            break;

                        default:
                            System.out.println("Invalid choice. Forwarding normally.");
                            out.write(buffer, 0, bytesRead);
                            out.flush();
                            break;
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
