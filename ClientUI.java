import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.Cipher;
import java.util.Base64;

public class ClientUI extends JFrame {
    private JTextField hostField, userField, passField, cmdField;
    private JTextArea logArea;
    private JButton connectButton, sendButton;
    private Socket socket;
    private DataInputStream in;
    private DataOutputStream out;
    private PublicKey serverPubKey;

    public ClientUI() {
        setTitle("SSHv2 Demo - Client");
        setSize(600, 400);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLayout(new BorderLayout());

        JPanel topPanel = new JPanel(new GridLayout(4, 2));
        hostField = new JTextField("localhost");
        userField = new JTextField("admin");
        passField = new JTextField("12345");
        cmdField = new JTextField("show date");
        topPanel.add(new JLabel("Host:")); topPanel.add(hostField);
        topPanel.add(new JLabel("Username:")); topPanel.add(userField);
        topPanel.add(new JLabel("Password:")); topPanel.add(passField);
        topPanel.add(new JLabel("Command:")); topPanel.add(cmdField);

        logArea = new JTextArea();
        logArea.setEditable(false);
        JScrollPane scroll = new JScrollPane(logArea);

        JPanel bottomPanel = new JPanel();
        connectButton = new JButton("Connect");
        sendButton = new JButton("Send Command");
        sendButton.setEnabled(false);
        connectButton.addActionListener(e -> connect());
        sendButton.addActionListener(e -> sendCommand());
        bottomPanel.add(connectButton);
        bottomPanel.add(sendButton);

        add(topPanel, BorderLayout.NORTH);
        add(scroll, BorderLayout.CENTER);
        add(bottomPanel, BorderLayout.SOUTH);
    }

    private void connect() {
        try {
            socket = new Socket(hostField.getText(), 8000);
            in = new DataInputStream(socket.getInputStream());
            out = new DataOutputStream(socket.getOutputStream());
            log("[Client] Connected to server.");

            String pubKeyStr = in.readUTF();
            byte[] pubBytes = Base64.getDecoder().decode(pubKeyStr);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            serverPubKey = kf.generatePublic(new java.security.spec.X509EncodedKeySpec(pubBytes));
            log("[Client] Received server public key.");

            // Send encrypted username:password
            String credentials = userField.getText() + ":" + passField.getText();
            Cipher rsa = Cipher.getInstance("RSA");
            rsa.init(Cipher.ENCRYPT_MODE, serverPubKey);
            byte[] encAuth = rsa.doFinal(credentials.getBytes());
            out.writeUTF(Base64.getEncoder().encodeToString(encAuth));
            log("[Client] Sent encrypted credentials.");

            String authResult = in.readUTF();
            if (authResult.equals("AUTH_SUCCESS")) {
                log("[Client] Authentication successful.");
                sendButton.setEnabled(true);
            } else {
                log("[Client] Authentication failed.");
                socket.close();
            }
        } catch (Exception e) {
            log("Error: " + e.getMessage());
        }
    }

    private void sendCommand() {
        try {
            Cipher rsa = Cipher.getInstance("RSA");
            rsa.init(Cipher.ENCRYPT_MODE, serverPubKey);
            byte[] encCmd = rsa.doFinal(cmdField.getText().getBytes());
            out.writeUTF(Base64.getEncoder().encodeToString(encCmd));
            log("[Client] Sent command: " + cmdField.getText());

            String encReply = in.readUTF();
            rsa.init(Cipher.DECRYPT_MODE, serverPubKey); // fake decrypt (for demo)
            String reply = new String(rsa.doFinal(Base64.getDecoder().decode(encReply)));
            log("[Client] Server replied: " + reply);
        } catch (Exception e) {
            log("Error: " + e.getMessage());
        }
    }

    private void log(String msg) {
        SwingUtilities.invokeLater(() -> logArea.append(msg + "\n"));
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new ClientUI().setVisible(true));
    }
}
