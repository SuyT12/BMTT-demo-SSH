import java.io.*;
import java.net.*;

public class SSHServer {
    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(8000)) {
            System.out.println("[Server] RSA SSH Demo started.");
            Socket socket = serverSocket.accept();
            System.out.println("[Server] Client connected.");

            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            SSHTransport transport = new SSHTransport(in, out);
            transport.setupServerKeys();
            transport.sendPublicKey();

            SSHAuthentication auth = new SSHAuthentication(in, out, transport);
            if (auth.handleAuthServer()) {
                SSHConnection conn = new SSHConnection(in, out, transport);
                conn.handleSessionServer();
            }

            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
