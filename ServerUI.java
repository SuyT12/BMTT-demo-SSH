import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.Cipher;
import java.util.Base64;

public class ServerUI extends JFrame {
    private JTextArea logArea;
    private JButton startButton;
    private ServerSocket serverSocket;

    public ServerUI() {
        setTitle("SSHv2 Demo - Server");
        setSize(600, 400);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLayout(new BorderLayout());

        logArea = new JTextArea();
        logArea.setEditable(false);
        JScrollPane scroll = new JScrollPane(logArea);

        startButton = new JButton("Start Server");
        startButton.addActionListener(e -> startServer());

        add(scroll, BorderLayout.CENTER);
        add(startButton, BorderLayout.SOUTH);
    }

    private void startServer() {
        startButton.setEnabled(false);
        new Thread(() -> {
            try {
                serverSocket = new ServerSocket(8000);
                log("[Server] Listening on port 8000...");
                Socket client = serverSocket.accept();
                log("[Server] Client connected: " + client.getInetAddress());

                DataInputStream in = new DataInputStream(client.getInputStream());
                DataOutputStream out = new DataOutputStream(client.getOutputStream());

                // Generate RSA keypair
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(2048);
                KeyPair pair = keyGen.generateKeyPair();
                PrivateKey privateKey = pair.getPrivate();
                PublicKey publicKey = pair.getPublic();

                // Send public key
                out.writeUTF(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
                log("[Server] Public key sent.");

                // Receive encrypted username/password
                String encAuth = in.readUTF();
                Cipher rsa = Cipher.getInstance("RSA");
                rsa.init(Cipher.DECRYPT_MODE, privateKey);
                String[] parts = new String(rsa.doFinal(Base64.getDecoder().decode(encAuth))).split(":");
                String user = parts[0], pass = parts[1];
                log("[Auth] Received login: " + user);

                if (user.equals("admin") && pass.equals("12345")) {
                    out.writeUTF("AUTH_SUCCESS");
                    log("[Auth] User authenticated.");
                } else {
                    out.writeUTF("AUTH_FAIL");
                    log("[Auth] Authentication failed.");
                    client.close();
                    return;
                }

                // Receive encrypted command
                String encCmd = in.readUTF();
                String cmd = new String(rsa.doFinal(Base64.getDecoder().decode(encCmd)));
                log("[Command] Received: " + cmd);

                // Execute simple command
                String result;
                if (cmd.equalsIgnoreCase("show date")) {
                    result = new java.util.Date().toString();
                } else {
                    result = "Unknown command: " + cmd;
                }

                // Encrypt and send result
                rsa.init(Cipher.ENCRYPT_MODE, privateKey); // fake send-back (should be client public)
                byte[] encryptedResult = rsa.doFinal(result.getBytes());
                out.writeUTF(Base64.getEncoder().encodeToString(encryptedResult));
                log("[Server] Sent response.");

                client.close();
                log("[Server] Connection closed.");
            } catch (Exception e) {
                log("Error: " + e.getMessage());
                e.printStackTrace();
            }
        }).start();
    }

    private void log(String msg) {
        SwingUtilities.invokeLater(() -> logArea.append(msg + "\n"));
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new ServerUI().setVisible(true));
    }
}
