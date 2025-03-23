// Alice.java
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Random;
import java.nio.ByteBuffer;

/**
 * Alice client for the extended Needham-Schroeder protocol.
 * Initiates authentication with KDC and completes mutual authentication with Bob.
 */
public class Alice {
    private static final long ALICE_ID = 1001;  // Alice's unique identifier
    private static final long BOB_ID = 1002;    // Bob's unique identifier
    
    /**
     * Main method to execute the authentication protocol.
     */
    public static void main(String[] args) throws Exception {
        // Generate a secure random 64-bit nonce
        Random rand = new SecureRandom();
        long nonce = rand.nextLong();
        System.out.println("Generated nonce: " + Long.toHexString(nonce));
        
        // Prepare and encrypt the request to KDC (Alice ID, Bob ID, Nonce)
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, KDC.aliceKey);
        byte[] request = cipher.doFinal(combineBytes(longToBytes(ALICE_ID), 
                                                    longToBytes(BOB_ID), 
                                                    longToBytes(nonce)));
        System.out.println("Encrypted request to KDC: " + bytesToHex(request));
        
        // Send request to KDC and receive response
        byte[] response = KDC.processRequest(request, ALICE_ID);
        System.out.println("Received response from KDC: " + bytesToHex(response));
        
        // Decrypt the response to extract session key and ticket
        cipher.init(Cipher.DECRYPT_MODE, KDC.aliceKey);
        byte[] decrypted = cipher.doFinal(response);
        System.out.println("Decrypted response: " + bytesToHex(decrypted));
        
        SecretKey sessionKey = extractSessionKey(decrypted);
        byte[] ticket = extractTicket(decrypted, sessionKey.getEncoded().length);
        System.out.println("Extracted session key: " + bytesToHex(sessionKey.getEncoded()));
        System.out.println("Extracted ticket: " + bytesToHex(ticket));
        
        // Authenticate with Bob using the session key and ticket
        authenticateWithBob(sessionKey, ticket, nonce);
    }
    
    /**
     * Completes authentication with Bob using the session key and ticket.
     * @param sessionKey Shared session key with Bob
     * @param ticket Encrypted ticket from KDC
     * @param nonce Original nonce for challenge
     */
    private static void authenticateWithBob(SecretKey sessionKey, byte[] ticket, long nonce) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey);
        byte[] message = cipher.doFinal(longToBytes(nonce));
        System.out.println("Encrypted nonce to Bob: " + bytesToHex(message));
        Bob.authenticate(message, ticket);
    }
    
    /**
     * Extracts the session key from the decrypted response.
     * @param data Decrypted response from KDC
     * @return Session key
     */
    private static SecretKey extractSessionKey(byte[] data) {
        byte[] keyBytes = new byte[24]; // 3DES key length is 24 bytes
        System.arraycopy(data, 0, keyBytes, 0, keyBytes.length);
        return new SecretKeySpec(keyBytes, "DESede");
    }
    
    /**
     * Extracts the ticket from the decrypted response.
     * @param data Decrypted response from KDC
     * @param keyLength Length of the session key
     * @return Ticket bytes
     */
    private static byte[] extractTicket(byte[] data, int keyLength) {
        byte[] ticket = new byte[data.length - keyLength];
        System.arraycopy(data, keyLength, ticket, 0, ticket.length);
        return ticket;
    }
    
    /**
     * Combines multiple byte arrays into a single array.
     * @param arrays Variable number of byte arrays
     * @return Combined byte array
     */
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
    
    /**
     * Converts a long value to a byte array (64-bit).
     * @param value Long value to convert
     * @return Byte array representation
     */
    private static byte[] longToBytes(long value) {
        return ByteBuffer.allocate(8).putLong(value).array();
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