import java.io.*;
import java.net.*;
import javax.crypto.*;


public class SSHServer {
    public static void main(String[] args) {
        int port = 8000;
        System.out.println("[Server] Starting SSH-2.0 Demo Server on port " + port + "...");

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            Socket socket = serverSocket.accept();
            System.out.println("[Server] Client connected: " + socket.getInetAddress());

            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            // --- Transport phase ---
            SSHTransport transport = new SSHTransport(in, out);
            transport.exchangeVersion("SSH-2.0-DemoServer");
            SecretKey aesKey = transport.performKeyExchange(true, null);
            
            // Sau khi thực hiện key exchange
            // Dùng aesKey mã hóa 1 thông điệp test gửi sang server
            Cipher testCipher = Cipher.getInstance("AES");
            testCipher.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] encrypted = testCipher.doFinal("Key established OK".getBytes());
            System.out.println("[Client] AES test message encrypted length: " + encrypted.length);


            // --- Authentication phase ---
            SSHAuthentication auth = new SSHAuthentication(in, out);
            boolean ok = auth.handleAuthServer("admin", "12345");

            if (ok) {
                // --- Connection phase ---
                SSHConnection conn = new SSHConnection(transport);
                conn.handleSessionServer();
            } else {
                System.out.println("[Server] Authentication failed.");
            }

            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
