import java.io.*;
import java.net.*;
import java.util.Base64;

import javax.crypto.SecretKey;

public class SSHClient {
    public static void main(String[] args) {
        try (Socket socket = new Socket("localhost", 8000)) {
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            // --- Transport phase ---
            SSHTransport transport = new SSHTransport(in, out);
            transport.exchangeVersion("SSH-2.0-DemoClient");
            SecretKey aesKey = transport.performKeyExchange(false, null);

            System.out.println("[Server] AES session key received: " + Base64.getEncoder().encodeToString(aesKey.getEncoded()));

            // --- Authentication phase ---
            SSHAuthentication auth = new SSHAuthentication(in, out);
            if (auth.handleAuthClient("admin", "12345")) {
                // --- Connection phase ---
                SSHConnection conn = new SSHConnection(transport);
                conn.handleSessionClient("show date");
            } else {
                System.out.println("[Client] Authentication failed!");
            }

            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
