// ReflectionAttack.java
import javax.crypto.*;
import java.security.*;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;

/**
 * Demonstrates a reflection attack on the original Needham-Schroeder protocol
 * using ECB mode, and shows how CBC mode prevents it.
 */
public class ReflectionAttack {
    /**
     * Demonstrates the reflection attack and ECB vs CBC difference.
     */
    public static void demonstrateAttack() throws Exception {
        // Generate a session key and nonce
        KeyGenerator keyGen = KeyGenerator.getInstance("DESede");
        SecretKey sessionKey = keyGen.generateKey();
        long nonceA = new SecureRandom().nextLong();
        byte[] iv = new byte[8]; // Original IV for CBC
        new SecureRandom().nextBytes(iv); // Randomize IV
        
        // Step 1: Alice sends encrypted nonce to Bob (ECB mode)
        Cipher ecbCipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        ecbCipher.init(Cipher.ENCRYPT_MODE, sessionKey);
        byte[] message1 = ecbCipher.doFinal(longToBytes(nonceA));
        System.out.println("Alice's encrypted nonce (ECB): " + bytesToHex(message1));
        
        // Step 2: Trudy replays the message to Bob
        System.out.println("Trudy replays message to Bob: " + bytesToHex(message1));
        ecbCipher.init(Cipher.DECRYPT_MODE, sessionKey);
        long recoveredNonce = bytesToLong(ecbCipher.doFinal(message1));
        System.out.println("Bob decrypts nonce (ECB): " + Long.toHexString(recoveredNonce));
        
        // Step 3: Bob responds with nonceA - 1
        ecbCipher.init(Cipher.ENCRYPT_MODE, sessionKey);
        byte[] message2 = ecbCipher.doFinal(longToBytes(recoveredNonce - 1));
        System.out.println("Bob's encrypted response (ECB): " + bytesToHex(message2));
        
        // Step 4: Trudy decrypts Bob's response
        ecbCipher.init(Cipher.DECRYPT_MODE, sessionKey);
        long finalNonce = bytesToLong(ecbCipher.doFinal(message2));
        System.out.println("Trudy recovers nonce - 1 (attack succeeds): " + Long.toHexString(finalNonce));
        
        // Step 5: Show CBC mode prevents the attack and compare last two messages
        Cipher cbcCipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        new SecureRandom().nextBytes(iv);
        cbcCipher.init(Cipher.ENCRYPT_MODE, sessionKey, new IvParameterSpec(iv));
        byte[] cbcMessage1 = cbcCipher.doFinal(longToBytes(nonceA));
        System.out.println("\nAlice's encrypted nonce (CBC): " + bytesToHex(cbcMessage1));
        
        // Bob's response in CBC mode (nonce - 1)
        byte[] cbcMessage2 = cbcCipher.doFinal(longToBytes(recoveredNonce - 1));
        System.out.println("Bob's encrypted response (CBC): " + bytesToHex(cbcMessage2));
        
        // Trudy replays with wrong IV
        byte[] wrongIV = new byte[8];
        new SecureRandom().nextBytes(wrongIV);
        cbcCipher.init(Cipher.DECRYPT_MODE, sessionKey, new IvParameterSpec(wrongIV));
        try {
            byte[] decrypted = cbcCipher.doFinal(cbcMessage1);
            long failedNonce = bytesToLong(decrypted);
            System.out.println("Decrypted nonce with wrong IV (garbage): " + Long.toHexString(failedNonce));
        } catch (BadPaddingException e) {
            System.out.println("CBC decryption fails with wrong IV (attack prevented)");
        }
    }
    
    public static void main(String[] args) throws Exception {
        demonstrateAttack();
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