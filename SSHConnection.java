import java.io.*;

public class SSHConnection {
    private SSHTransport transport;

    public SSHConnection(SSHTransport transport) {
        this.transport = transport;
    }

    // Client gửi lệnh
    public void handleSessionClient(String command) throws Exception {
        DataOutputStream out = transport.getOutputStream();
        DataInputStream in = transport.getInputStream();

        out.writeUTF(command);
        out.flush();
        String result = in.readUTF();
        System.out.println("[Client] Server replied: " + result);
    }

    // Server thực thi lệnh
    public void handleSessionServer() throws Exception {
        DataInputStream in = transport.getInputStream();
        DataOutputStream out = transport.getOutputStream();

        String cmd = in.readUTF();
        System.out.println("[Server] Received command: " + cmd);

        String result;
        if (cmd.equalsIgnoreCase("show date")) {
            result = new java.util.Date().toString();
        } else if (cmd.equalsIgnoreCase("hello")) {
            result = "Hello from SSH Demo Server!";
        } else {
            result = "Unknown command.";
        }

        out.writeUTF(result);
        out.flush();
    }
}
