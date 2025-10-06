import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class SSHServer {
    public static void main(String[] args) {
        int port = 8000;

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("SSH Server started on port " + port);
            System.out.println("Waiting for client connection...");

            Socket socket = serverSocket.accept();
            System.out.println("Client connected: " + socket.getInetAddress());

            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            // 1️⃣ Trao đổi version
            String clientVersion = in.readUTF();
            System.out.println("Client version: " + clientVersion);
            out.writeUTF("SSH-1.0-MiniServer");

            // 2️⃣ Sinh cặp khóa RSA (mô phỏng server public/private key)
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair pair = keyGen.generateKeyPair();
            PrivateKey privateKey = pair.getPrivate();
            PublicKey publicKey = pair.getPublic();

            // Gửi public key cho client
            out.writeUTF(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
            System.out.println("Public key sent to client.");

            // 3️⃣ Nhận secret key mã hóa (đã mã hóa RSA)
            String encryptedSecretKey = in.readUTF();
            byte[] decodedKey = Base64.getDecoder().decode(encryptedSecretKey);

            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] secretKeyBytes = rsaCipher.doFinal(decodedKey);

            SecretKey aesKey = new SecretKeySpec(secretKeyBytes, 0, secretKeyBytes.length, "AES");
            System.out.println("AES key received and decrypted.");

            // 4️⃣ Nhận tin nhắn mã hóa từ client
            String encryptedMsg = in.readUTF();
            Cipher aesCipher = Cipher.getInstance("AES");
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
            byte[] decryptedMsg = aesCipher.doFinal(Base64.getDecoder().decode(encryptedMsg));
            String message = new String(decryptedMsg);
            System.out.println("Client message (decrypted): " + message);

            // 5️⃣ Gửi phản hồi lại client (mã hóa bằng cùng AES key)
            String reply = "Message received securely: " + message.toUpperCase();
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] encryptedReply = aesCipher.doFinal(reply.getBytes());
            out.writeUTF(Base64.getEncoder().encodeToString(encryptedReply));
            System.out.println("Reply sent to client.");

            socket.close();
            System.out.println("Connection closed.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
