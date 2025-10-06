import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.*;
import java.util.Base64;
import java.util.Scanner;

public class SSHClient {
    public static void main(String[] args) {
        String host = "localhost";
        int port = 8000;

        try (Socket socket = new Socket(host, port)) {
            System.out.println("Connected to SSH server " + host + ":" + port);
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            // 1️⃣ Gửi version
            out.writeUTF("SSH-1.0-MiniClient");
            String serverVersion = in.readUTF();
            System.out.println("Server version: " + serverVersion);

            // 2️⃣ Nhận public key từ server
            String serverPubKeyStr = in.readUTF();
            byte[] decodedPubKey = Base64.getDecoder().decode(serverPubKeyStr);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey serverPubKey = keyFactory.generatePublic(new X509EncodedKeySpec(decodedPubKey));
            System.out.println("Received server public key.");

            // 3️⃣ Tạo khóa bí mật AES và mã hóa bằng public key RSA của server
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            SecretKey aesKey = keyGen.generateKey();

            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.ENCRYPT_MODE, serverPubKey);
            byte[] encryptedSecretKey = rsaCipher.doFinal(aesKey.getEncoded());
            out.writeUTF(Base64.getEncoder().encodeToString(encryptedSecretKey));
            System.out.println("AES secret key sent to server.");

            // 4️⃣ Nhập tin nhắn từ bàn phím và gửi đi
            Scanner scanner = new Scanner(System.in);
            System.out.print("Enter message to send securely: ");
            String msg = scanner.nextLine();

            Cipher aesCipher = Cipher.getInstance("AES");
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] encryptedMsg = aesCipher.doFinal(msg.getBytes());
            out.writeUTF(Base64.getEncoder().encodeToString(encryptedMsg));
            System.out.println("Encrypted message sent.");

            // 5️⃣ Nhận phản hồi từ server
            String encryptedReply = in.readUTF();
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
            byte[] decryptedReply = aesCipher.doFinal(Base64.getDecoder().decode(encryptedReply));
            String reply = new String(decryptedReply);
            System.out.println("[Server] " + reply);

            // Sau khi gửi tin nhắn, trước khi đóng socket:
            scanner.close();
            socket.close();
            System.out.println("Connection closed.");


            socket.close();
            System.out.println("Connection closed.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
