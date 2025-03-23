// KDC.java
import javax.crypto.*;
import java.security.*;
import java.nio.ByteBuffer;
/**
 * Key Distribution Center (KDC) for the Needham-Schroeder protocol.
 * Manages shared keys with Alice and Bob, and issues session keys and tickets.
 */
public class KDC {
    public static final SecretKey aliceKey;  // Shared key with Alice
    public static final SecretKey bobKey;    // Shared key with Bob
    
    static {
        try {
            // Generate 3DES keys for Alice and Bob during class initialization
            KeyGenerator keyGen = KeyGenerator.getInstance("DESede");
            aliceKey = keyGen.generateKey();
            bobKey = keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to initialize KDC keys", e);
        }
    }

    /**
     * Processes Alice's authentication request and returns an encrypted response
     * containing the session key and ticket.
     * @param message Encrypted request from Alice
     * @param aliceId Alice's unique identifier
     * @return Encrypted response containing session key and ticket
     */
    public static byte[] processRequest(byte[] message, long aliceId) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aliceKey);
        byte[] decrypted = cipher.doFinal(message);
        
        KeyGenerator keyGen = KeyGenerator.getInstance("DESede");
        SecretKey sessionKey = keyGen.generateKey();
        
        byte[] ticket = createTicket(sessionKey, aliceId);
        cipher.init(Cipher.ENCRYPT_MODE, aliceKey);
        return cipher.doFinal(combineBytes(sessionKey.getEncoded(), ticket));
    }
    
    private static byte[] createTicket(SecretKey sessionKey, long aliceId) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, bobKey);
        return cipher.doFinal(combineBytes(sessionKey.getEncoded(), longToBytes(aliceId)));
    }
    
    private static byte[] combineBytes(byte[]... arrays) {
        int totalLength = 0;
        for (byte[] array : arrays) {
            totalLength += array.length;
        }
        
        byte[] result = new byte[totalLength];
        int offset = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, offset, array.length);
            offset += array.length;
        }
        return result;
    }
    
    private static byte[] longToBytes(long value) {
        return ByteBuffer.allocate(8).putLong(value).array();
    }
}