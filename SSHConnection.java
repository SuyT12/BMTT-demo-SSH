import java.io.*;
import java.security.PublicKey;

public class SSHConnection {
    private DataInputStream in;
    private DataOutputStream out;
    private SSHTransport transport;

    public SSHConnection(DataInputStream in, DataOutputStream out, SSHTransport transport) {
        this.in = in;
        this.out = out;
        this.transport = transport;
    }

    // Client gửi lệnh
    public void handleSessionClient(String command, PublicKey pubKey) throws Exception {
        String enc = transport.encryptMessage(command, pubKey);
        out.writeUTF(enc);
        String encReply = in.readUTF();
        String reply = transport.decryptMessage(encReply);
        System.out.println("[Client] Server replied: " + reply);
    }

    // Server thực thi
    public void handleSessionServer() throws Exception {
        String encCmd = in.readUTF();
        String cmd = transport.decryptMessage(encCmd);
        System.out.println("[Server] Received command: " + cmd);

        String result = cmd.equalsIgnoreCase("show date") ?
                new java.util.Date().toString() : "Unknown command.";

        String encReply = transport.encryptMessage(result, transport.getServerPublicKey());
        out.writeUTF(encReply);
    }
}
