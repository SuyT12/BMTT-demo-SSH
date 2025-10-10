import java.io.*;
import java.net.*;
import java.security.PublicKey;

public class SSHClient {
    public static void main(String[] args) {
        try (Socket socket = new Socket("localhost", 8000)) {
            System.out.println("[Client] Connected to server.");

            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            SSHTransport transport = new SSHTransport(in, out);
            PublicKey serverPub = transport.receivePublicKey();

            SSHAuthentication auth = new SSHAuthentication(in, out, transport);
            if (auth.handleAuthClient("admin", "12345", serverPub)) {
                SSHConnection conn = new SSHConnection(in, out, transport);
                conn.handleSessionClient("show date", serverPub);
            } else {
                System.out.println("[Client] Authentication failed.");
            }

            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
