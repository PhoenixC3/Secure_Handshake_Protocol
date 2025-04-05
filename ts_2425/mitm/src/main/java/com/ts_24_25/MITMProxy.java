package com.ts_24_25;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.io.File;
import java.io.FileWriter;
import java.io.FileReader;
import java.io.BufferedReader;
import java.awt.Desktop;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.xml.bind.DatatypeConverter;

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
                
                // Only use one thread per ProxyThread instance to avoid conflicts
                forwardData(inputStream, outputStream);
            } catch (IOException e) {
                System.err.println("Error in " + direction + ": " + e.getMessage());
                e.printStackTrace();
            } finally {
                // Ensure sockets are properly closed when done
                try {
                    if (!inputSocket.isClosed()) {
                        inputSocket.close();
                    }
                    if (!outputSocket.isClosed()) {
                        outputSocket.close();
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        // Forward data between input and output
        private void forwardData(InputStream in, OutputStream out) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            Scanner scanner = new Scanner(System.in);

            try {
                while (true) {
                    try {
                        // Use available() to check if there's data to read without blocking
                        if (in.available() > 0) {
                            bytesRead = in.read(buffer);
                            
                            // Check for end of stream
                            if (bytesRead == -1) {
                                System.out.println("[" + this.direction + "] Connection closed by remote host");
                                break;
                            }
                            
                            // Convert raw bytes to hex string
                            byte[] messageBytes = new byte[bytesRead];
                            System.arraycopy(buffer, 0, messageBytes, 0, bytesRead);
                            String hexMessage = bytesToHex(messageBytes);
                            
                            // Store original bytes for forwarding unchanged
                            String interceptedMessage = hexMessage;
                            messageHistory.add(interceptedMessage); // Store message for replaying
                            System.out.println("Intercepted [" + this.direction + "] (hex): " + interceptedMessage);

                            System.out.println("Choose an action:");
                            System.out.println("1) Forward message unchanged");
                            System.out.println("2) Modify message");
                            System.out.println("3) Drop message");
                            System.out.print("Enter choice (1-4): ");
                            int choice = scanner.nextInt();
                            scanner.nextLine();

                            switch (choice) {
                                case 1: // Forward message unchanged
                                    out.write(buffer, 0, bytesRead);
                                    out.flush();
                                    break;

                                case 2: // Modify message
                                    try {
                                        // Create a temporary file with the intercepted message
                                        File tempFile = File.createTempFile("mitm_message_", ".txt");
                                        tempFile.deleteOnExit(); // Ensure file is deleted on JVM exit
                                        
                                        // Write intercepted message to the file in hex format
                                        try (FileWriter writer = new FileWriter(tempFile)) {
                                            writer.write(interceptedMessage);
                                        }
                                        
                                        System.out.println("Message saved to: " + tempFile.getAbsolutePath());
                                        System.out.println("Opening file in default editor...");
                                        
                                        // Open the file in the default system editor
                                        if (Desktop.isDesktopSupported()) {
                                            Desktop.getDesktop().edit(tempFile);
                                        } else {
                                            System.out.println("Desktop not supported. Please edit the file manually: " + tempFile.getAbsolutePath());
                                        }
                                        
                                        System.out.println("Edit the message in the opened editor, save the file, then press Enter to continue...");
                                        scanner.nextLine(); // Wait for user to press Enter after editing
                                        
                                        // Read the modified content from the file
                                        String modifiedHexMessage = new String(Files.readAllBytes(Paths.get(tempFile.getAbsolutePath())));
                                        
                                        // Check if the message was actually modified
                                        if (!modifiedHexMessage.equals(interceptedMessage)) {
                                            System.out.println("Modified message (hex): " + modifiedHexMessage);
                                            
                                            // Convert hex string back to bytes and send
                                            byte[] modifiedBytes = hexToBytes(modifiedHexMessage);
                                            out.write(modifiedBytes);
                                            out.flush();
                                        } else {
                                            System.out.println("No changes detected. Forwarding original message.");
                                            out.write(buffer, 0, bytesRead);
                                            out.flush();
                                        }
                                        
                                        // Delete the temporary file
                                        if (tempFile.delete()) {
                                            System.out.println("Temporary file deleted successfully.");
                                        } else {
                                            System.out.println("Failed to delete temporary file. It will be deleted on JVM exit.");
                                        }
                                    } catch (IOException e) {
                                        System.err.println("Error handling file-based message editing: " + e.getMessage());
                                        e.printStackTrace();
                                        
                                        // Fallback to console input if file editing fails
                                        System.out.print("Enter modified message (in hex format): ");
                                        String modifiedHexMessage = scanner.nextLine();
                                        byte[] modifiedBytes = hexToBytes(modifiedHexMessage);
                                        out.write(modifiedBytes);
                                        out.flush();
                                    }
                                    break;

                                case 3: // Drop message
                                    System.out.println("Message dropped.");
                                    break;
                                default:
                                    System.out.println("Invalid choice. Forwarding normally.");
                                    out.write(buffer, 0, bytesRead);
                                    out.flush();
                                    break;
                            }
                        } else {
                            // No data available, check if socket is still connected
                            if (inputSocket.isClosed() || !inputSocket.isConnected() || outputSocket.isClosed() || !outputSocket.isConnected()) {
                                System.out.println("[" + this.direction + "] Connection closed");
                                break;
                            }
                            // Small sleep to prevent CPU spinning
                            Thread.sleep(10);
                        }
                    } catch (java.net.SocketException se) {
                        System.out.println("[" + this.direction + "] Socket exception: " + se.getMessage());
                        break;
                    } catch (InterruptedException ie) {
                        System.out.println("[" + this.direction + "] Thread interrupted");
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            } catch (IOException e) {
                System.err.println("[" + this.direction + "] IO error: " + e.getMessage());
            }
        }
    }
    
    // Utility method to convert bytes to hex string
    private static String bytesToHex(byte[] bytes) {
        return DatatypeConverter.printHexBinary(bytes);
    }
    
    // Utility method to convert hex string back to bytes
    private static byte[] hexToBytes(String hexString) {
        // Remove any whitespace or non-hex characters
        hexString = hexString.replaceAll("[^0-9A-Fa-f]", "");
        return DatatypeConverter.parseHexBinary(hexString);
    }
}
