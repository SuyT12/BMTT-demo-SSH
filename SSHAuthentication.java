import java.io.*;
import java.security.PublicKey;

public class SSHAuthentication {
    private DataInputStream in;
    private DataOutputStream out;
    private SSHTransport transport;

    public SSHAuthentication(DataInputStream in, DataOutputStream out, SSHTransport transport) {
        this.in = in;
        this.out = out;
        this.transport = transport;
    }

    // Client xác thực user
    public boolean handleAuthClient(String username, String password, PublicKey pubKey) throws Exception {
        String creds = username + ":" + password;
        String enc = transport.encryptMessage(creds, pubKey);
        out.writeUTF(enc);
        System.out.println("[Auth] Sent encrypted credentials.");
        String resp = in.readUTF();
        return resp.equals("OK");
    }

    // Server xử lý xác thực
    public boolean handleAuthServer() throws Exception {
        String enc = in.readUTF();
        String creds = transport.decryptMessage(enc);
        System.out.println("[Auth] Received credentials: " + creds);
        if (creds.equals("admin:12345")) {
            out.writeUTF("OK");
            System.out.println("[Auth] Authentication success.");
            return true;
        } else {
            out.writeUTF("FAIL");
            System.out.println("[Auth] Authentication failed.");
            return false;
        }
    }
}
