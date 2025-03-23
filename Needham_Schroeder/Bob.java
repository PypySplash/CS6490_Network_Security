// Bob.java
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.nio.ByteBuffer;

/**
 * Bob client for the extended Needham-Schroeder protocol.
 * Verifies Alice's authentication request and responds with a challenge response.
 */
public class Bob {
    private static final long BOB_ID = 1002;  // Bob's unique identifier
    
    /**
     * Authenticates Alice's request using the ticket and encrypted nonce.
     * @param message Encrypted nonce from Alice
     * @param ticket Encrypted ticket from KDC
     */
    public static void authenticate(byte[] message, byte[] ticket) throws Exception {
        // Decrypt the ticket using Bob's shared key with KDC
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, KDC.bobKey);
        byte[] ticketContent = cipher.doFinal(ticket);
        System.out.println("Decrypted ticket: " + bytesToHex(ticketContent));
        
        // Extract the session key from the ticket
        SecretKey sessionKey = extractSessionKey(ticketContent);
        System.out.println("Extracted session key: " + bytesToHex(sessionKey.getEncoded()));
        
        // Decrypt Alice's message and verify the nonce
        cipher.init(Cipher.DECRYPT_MODE, sessionKey);
        long nonce = bytesToLong(cipher.doFinal(message));
        long responseNonce = nonce - 1;
        
        System.out.println("Authentication successful!");
        System.out.println("Received nonce: " + Long.toHexString(nonce));
        System.out.println("Sending response: " + Long.toHexString(responseNonce));
    }
    
    /**
     * Extracts the session key from the decrypted ticket.
     * @param data Decrypted ticket content
     * @return Session key
     */
    private static SecretKey extractSessionKey(byte[] data) {
        byte[] keyBytes = new byte[24]; // 3DES key length is 24 bytes
        System.arraycopy(data, 0, keyBytes, 0, keyBytes.length);
        return new SecretKeySpec(keyBytes, "DESede");
    }
    
    /**
     * Converts a byte array to a long value (64-bit).
     * @param bytes Byte array to convert
     * @return Long value
     */
    private static long bytesToLong(byte[] bytes) {
        return ByteBuffer.wrap(bytes).getLong();
    }
    
    /**
     * Converts a byte array to a hexadecimal string.
     * @param bytes Byte array to convert
     * @return Hexadecimal string
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}