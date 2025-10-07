import java.io.*;

public class SSHAuthentication {
    private DataInputStream in;
    private DataOutputStream out;

    public SSHAuthentication(DataInputStream in, DataOutputStream out) {
        this.in = in;
        this.out = out;
    }

    // Client gửi username + password
    public boolean handleAuthClient(String username, String password) throws IOException {
        out.writeUTF(username);
        out.writeUTF(password);
        String response = in.readUTF();

        if (response.equals("AUTH_SUCCESS")) {
            System.out.println("[Auth] Authenticated as " + username);
            return true;
        } else {
            System.out.println("[Auth] Login failed");
            return false;
        }
    }

    // Server xác thực
    public boolean handleAuthServer(String validUser, String validPass) throws IOException {
        String username = in.readUTF();
        String password = in.readUTF();
        System.out.println("[Auth] Attempt: " + username);

        if (username.equals(validUser) && password.equals(validPass)) {
            out.writeUTF("AUTH_SUCCESS");
            System.out.println("[Auth] Client authenticated successfully!");
            return true;
        } else {
            out.writeUTF("AUTH_FAIL");
            return false;
        }
    }
}
