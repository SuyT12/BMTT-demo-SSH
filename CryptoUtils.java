import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class CryptoUtils {

    // ======================== RSA =========================
    public static KeyPair generateRSAKeyPair(int keySize) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(keySize);
        return kpg.generateKeyPair();
    }

    public static byte[] publicKeyToBytes(PublicKey pub) {
        return pub.getEncoded();
    }

    public static PublicKey bytesToPublicKey(byte[] data) throws Exception {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public static byte[] encryptRSA(byte[] data, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static byte[] decryptRSA(byte[] data, PrivateKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    // ======================== AES =========================
    public static SecretKey generateAESKey(int bits) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(bits);
        return kg.generateKey();
    }

    public static class AESResult {
        public byte[] iv;
        public byte[] cipher;
        public AESResult(byte[] iv, byte[] cipher) {
            this.iv = iv;
            this.cipher = cipher;
        }
    }

    public static AESResult encryptAES(byte[] plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] enc = cipher.doFinal(plaintext);
        return new AESResult(iv, enc);
    }

    public static byte[] decryptAES(byte[] iv, byte[] cipherText, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        return cipher.doFinal(cipherText);
    }

    public static SecretKey restoreAESKey(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
    }

    // ======================== HMAC =========================
    public static SecretKey deriveHmacKeyFromAes(SecretKey aesKey) throws Exception {
        // Đơn giản hóa: hash AES key để lấy HMAC key
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hmacBytes = sha256.digest(aesKey.getEncoded());
        return new SecretKeySpec(hmacBytes, "HmacSHA256");
    }

    public static byte[] computeHMAC(byte[] data, SecretKey hmacKey) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(hmacKey);
        return mac.doFinal(data);
    }

    // ======================== Fingerprint =========================
    public static String sha256Fingerprint(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data);
        return Base64.getEncoder().encodeToString(hash);
    }

    // ======================== Tiện ích =========================
    public static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}
