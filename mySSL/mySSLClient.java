import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class mySSLClient {
    private static final String HOST = "localhost";           // Server hostname
    private static final int PORT = 8443;                    // Server port
    private static final String CERT_FILE = "client_cert.pem";  // Client certificate file
    private static final String KEY_FILE = "client_key.pem";    // Client private key file
    private static final String OUTPUT_FILE = "received.txt";   // Received file output
    private static final String FILE_TO_SEND = "sample.txt";    // Original file for verification

    public static void main(String[] args) {
        try {
            // Establish TCP connection to server
            Socket socket = new Socket(HOST, PORT);
            System.out.println("Connected to server");

            // Set up object streams for communication
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            // Load client certificate and private key
            X509Certificate clientCert = loadCertificate(CERT_FILE);
            PrivateKey clientPrivateKey = loadPrivateKey(KEY_FILE);

            // Step 1: Receive server certificate and extract public key
            X509Certificate serverCert = (X509Certificate) in.readObject();
            PublicKey serverPublicKey = serverCert.getPublicKey();

            // Step 2: Send client certificate to server
            out.writeObject(clientCert);
            out.flush();

            // Step 3: Generate and encrypt client nonce with server's public key
            SecureRandom random = new SecureRandom();
            byte[] clientNonce = new byte[32];
            random.nextBytes(clientNonce);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
            byte[] encryptedClientNonce = cipher.doFinal(clientNonce);
            out.writeObject(encryptedClientNonce);
            out.flush();

            // Step 4: Receive and decrypt server nonce with client's private key
            byte[] encryptedServerNonce = (byte[]) in.readObject();
            cipher.init(Cipher.DECRYPT_MODE, clientPrivateKey);
            byte[] serverNonce = cipher.doFinal(encryptedServerNonce);

            // Step 5: Generate master secret by XORing client and server nonces
            byte[] masterSecret = xorBytes(clientNonce, serverNonce);

            // Step 6: Compute and verify handshake hash
            String allMessages = serverCert.toString() + clientCert.toString() +
                    Base64.getEncoder().encodeToString(encryptedServerNonce) +
                    Base64.getEncoder().encodeToString(encryptedClientNonce);
            byte[] hash = computeKeyedHash(allMessages, masterSecret, "CLIENT");
            out.writeObject(hash);
            byte[] serverHash = (byte[]) in.readObject();
            byte[] expectedServerHash = computeKeyedHash(allMessages, masterSecret, "SERVER");

            // Verify server hash; if failed, close connection
            if (!MessageDigest.isEqual(serverHash, expectedServerHash)) {
                System.out.println("Handshake verification failed!");
                socket.close();
                return;
            }
            System.out.println("Handshake verification successful");

            // Generate four symmetric keys from master secret
            byte[][] keys = generateKeys(masterSecret);
            SecretKey encKey = new SecretKeySpec(keys[2], "AES");      // Server-to-client encryption key
            SecretKey macKey = new SecretKeySpec(keys[3], "HmacSHA1"); // Server-to-client MAC key

            // Receive encrypted file from server
            receiveFile(OUTPUT_FILE, in, encKey, macKey);
            System.out.println("File received successfully");

            // Verify received file against original
            verifyFile(FILE_TO_SEND, OUTPUT_FILE);

            // Close connection
            socket.close();
        } catch (ConnectException e) {
            // Handle connection failure
            System.err.println("Cannot connect to server: " + e.getMessage());
        } catch (IOException e) {
            // Handle I/O errors
            System.err.println("I/O error: " + e.getMessage());
        } catch (Exception e) {
            // Handle unexpected errors
            System.err.println("Unexpected error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // Loads client's X.509 certificate from a PEM file
    private static X509Certificate loadCertificate(String filename) throws Exception {
        FileInputStream fis = new FileInputStream(filename);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
        fis.close();
        return cert;
    }

    // Loads client's private key from a PEM file
    private static PrivateKey loadPrivateKey(String filename) throws Exception {
        String keyPem = new String(Files.readAllBytes(Paths.get(filename)));
        keyPem = keyPem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] keyBytes = Base64.getDecoder().decode(keyPem);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    // XORs two byte arrays to generate master secret
    private static byte[] xorBytes(byte[] a, byte[] b) {
        byte[] result = new byte[Math.min(a.length, b.length)];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    // Computes HMAC-SHA1 hash of data with a key and role suffix
    private static byte[] computeKeyedHash(String data, byte[] key, String role) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA1");
        SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA1");
        mac.init(keySpec);
        return mac.doFinal((data + role).getBytes());
    }

    // Generates four 16-byte keys from master secret using SHA-256
    private static byte[][] generateKeys(byte[] masterSecret) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(masterSecret);
        byte[][] keys = new byte[4][16];
        System.arraycopy(hash, 0, keys[0], 0, 16);   // Client-to-server encryption key
        System.arraycopy(hash, 16, keys[1], 0, 16);  // Client-to-server MAC key
        byte[] extendedHash = md.digest(hash);       // Generate additional bytes
        System.arraycopy(extendedHash, 0, keys[2], 0, 16);  // Server-to-client encryption key
        System.arraycopy(extendedHash, 16, keys[3], 0, 16); // Server-to-client MAC key
        return keys;
    }

    // Receives and decrypts file from server with AES and verifies a single HMAC-SHA1 for the entire file
    private static void receiveFile(String filename, ObjectInputStream in,
                                    SecretKey encKey, SecretKey macKey) throws Exception {
        // Receive encrypted data and MAC
        byte[] encryptedData = (byte[]) in.readObject();
        byte[] receivedMac = (byte[]) in.readObject();

        // Verify MAC for the entire encrypted data
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(macKey);
        byte[] computedMac = mac.doFinal(encryptedData);
        if (!MessageDigest.isEqual(receivedMac, computedMac)) {
            throw new SecurityException("MAC verification failed for the entire file");
        }

        // Decrypt the entire file
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, encKey);
        byte[] decryptedData = cipher.doFinal(encryptedData);

        // Write decrypted data to file
        FileOutputStream fos = new FileOutputStream(filename);
        fos.write(decryptedData);
        fos.close();
    }

    // Verifies if received file matches the original file
    private static void verifyFile(String original, String received) throws Exception {
        byte[] origBytes = Files.readAllBytes(Paths.get(original));
        byte[] recvBytes = Files.readAllBytes(Paths.get(received));
        if (MessageDigest.isEqual(origBytes, recvBytes)) {
            System.out.println("File verification successful");
        } else {
            System.out.println("File verification failed");
        }
    }
}