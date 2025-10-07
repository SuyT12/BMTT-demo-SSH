import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class SSHTransport {
    private DataInputStream in;
    private DataOutputStream out;
    private SecretKey aesKey;

    public SSHTransport(DataInputStream in, DataOutputStream out) {
        this.in = in;
        this.out = out;
    }

    public SecretKey getAESKey() {
        return this.aesKey;
    }

    public DataOutputStream getOut() {
        return this.out;
    }
    public DataInputStream getInputStream() {
    return in;
    }

    public DataOutputStream getOutputStream() {
    return out;
    }


    // Trao đổi phiên bản
    public void exchangeVersion(String version) throws IOException {
        out.writeUTF(version);
        String remoteVersion = in.readUTF();
        System.out.println("[Transport] Connected to " + remoteVersion);
    }

    // Mô phỏng trao đổi khóa theo kiểu RSA + AES session key
    public SecretKey performKeyExchange(boolean isServer, SecretKey existingKey) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();

        if (isServer) {
            // Server: gửi public key
            out.writeUTF(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));

            // Nhận AES key đã mã hóa
            String encKeyStr = in.readUTF();
            byte[] encKey = Base64.getDecoder().decode(encKeyStr);

            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.DECRYPT_MODE, pair.getPrivate());
            byte[] aesBytes = rsaCipher.doFinal(encKey);

            SecretKey aesKey = new SecretKeySpec(aesBytes, 0, aesBytes.length, "AES");
            System.out.println("[Transport] Session key established.");
            return aesKey;
        } else {
            // Client: nhận public key
            String pubKeyStr = in.readUTF();
            byte[] pubKeyBytes = Base64.getDecoder().decode(pubKeyStr);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey pubKey = kf.generatePublic(new java.security.spec.X509EncodedKeySpec(pubKeyBytes));

            // Sinh AES session key
            KeyGenerator aesGen = KeyGenerator.getInstance("AES");
            aesGen.init(128);
            SecretKey aesKey = aesGen.generateKey();

            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.ENCRYPT_MODE, pubKey);
            byte[] encKey = rsaCipher.doFinal(aesKey.getEncoded());

            out.writeUTF(Base64.getEncoder().encodeToString(encKey));
            System.out.println("[Transport] Sent AES session key securely.");
            return aesKey;
        }
    }
}
