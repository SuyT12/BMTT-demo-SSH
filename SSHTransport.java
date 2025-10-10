import java.io.*;
import java.security.*;
import java.util.Base64;
import javax.crypto.Cipher;

public class SSHTransport {
    private DataInputStream in;
    private DataOutputStream out;
    private KeyPair serverKeyPair;
    private PublicKey serverPublicKey;

    public SSHTransport(DataInputStream in, DataOutputStream out) {
        this.in = in;
        this.out = out;
    }

    // Server khởi tạo khoá RSA
    public void setupServerKeys() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        serverKeyPair = keyGen.generateKeyPair();
        serverPublicKey = serverKeyPair.getPublic();
    }

    // Gửi public key cho client
    public void sendPublicKey() throws Exception {
        String pubKeyStr = Base64.getEncoder().encodeToString(serverPublicKey.getEncoded());
        out.writeUTF(pubKeyStr);
        System.out.println("[Transport] Server sent public key to client.");
    }

    // Client nhận public key
    public PublicKey receivePublicKey() throws Exception {
        String pubKeyStr = in.readUTF();
        byte[] pubBytes = Base64.getDecoder().decode(pubKeyStr);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pubKey = kf.generatePublic(new java.security.spec.X509EncodedKeySpec(pubBytes));
        System.out.println("[Transport] Client received server public key.");
        return pubKey;
    }

    // Server giải mã tin nhắn
    public String decryptMessage(String encryptedBase64) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, serverKeyPair.getPrivate());
        byte[] decoded = Base64.getDecoder().decode(encryptedBase64);
        return new String(cipher.doFinal(decoded));
    }

    // Client mã hoá tin nhắn
    public String encryptMessage(String msg, PublicKey pubKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] enc = cipher.doFinal(msg.getBytes());
        return Base64.getEncoder().encodeToString(enc);
    }

    public PublicKey getServerPublicKey() {
        return serverPublicKey;
    }
}
