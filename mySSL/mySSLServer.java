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

public class mySSLServer {
    private static final int PORT = 8443;              // Server listening port
    private static final String CERT_FILE = "server_cert.pem";  // Server certificate file
    private static final String KEY_FILE = "server_key.pem";    // Server private key file
    private static final String FILE_TO_SEND = "sample.txt";    // File to send to client

    public static void main(String[] args) {
        try {
            // Create server socket to listen for client connections
            ServerSocket serverSocket = new ServerSocket(PORT);
            System.out.println("Server started on port " + PORT);

            while (true) {
                // Accept incoming client connection
                Socket clientSocket = serverSocket.accept();
                System.out.println("New client connected");

                // Set up object streams for communication
                ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
                ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());

                // Load server certificate and private key
                X509Certificate serverCert = loadCertificate(CERT_FILE);
                PrivateKey serverPrivateKey = loadPrivateKey(KEY_FILE);

                // Step 1: Send server certificate to client
                out.writeObject(serverCert);
                out.flush();

                // Step 2: Receive client certificate and extract public key
                X509Certificate clientCert = (X509Certificate) in.readObject();
                PublicKey clientPublicKey = clientCert.getPublicKey();

                // Step 3: Generate and encrypt server nonce with client's public key
                SecureRandom random = new SecureRandom();
                byte[] serverNonce = new byte[32];
                random.nextBytes(serverNonce);
                Cipher cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.ENCRYPT_MODE, clientPublicKey);
                byte[] encryptedServerNonce = cipher.doFinal(serverNonce);
                out.writeObject(encryptedServerNonce);
                out.flush();

                // Step 4: Receive and decrypt client nonce with server's private key
                byte[] encryptedClientNonce = (byte[]) in.readObject();
                cipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
                byte[] clientNonce = cipher.doFinal(encryptedClientNonce);

                // Step 5: Generate master secret by XORing server and client nonces
                byte[] masterSecret = xorBytes(serverNonce, clientNonce);

                // Step 6: Compute and verify handshake hash
                String allMessages = serverCert.toString() + clientCert.toString() +
                        Base64.getEncoder().encodeToString(encryptedServerNonce) +
                        Base64.getEncoder().encodeToString(encryptedClientNonce);
                byte[] hash = computeKeyedHash(allMessages, masterSecret, "SERVER");
                out.writeObject(hash);
                byte[] clientHash = (byte[]) in.readObject();
                byte[] expectedClientHash = computeKeyedHash(allMessages, masterSecret, "CLIENT");

                // Verify client hash; if failed, close connection
                if (!MessageDigest.isEqual(clientHash, expectedClientHash)) {
                    System.out.println("Handshake verification failed!");
                    clientSocket.close();
                    continue;
                }
                System.out.println("Handshake verification successful");

                // Generate four symmetric keys from master secret
                byte[][] keys = generateKeys(masterSecret);
                SecretKey encKey = new SecretKeySpec(keys[2], "AES");      // Server-to-client encryption key
                SecretKey macKey = new SecretKeySpec(keys[3], "HmacSHA1"); // Server-to-client MAC key

                // Send encrypted file to client
                sendFile(FILE_TO_SEND, out, encKey, macKey);
                System.out.println("File transfer completed successfully");

                // Close client connection
                clientSocket.close();
            }
        } catch (Exception e) {
            // Handle any server-side errors
            System.err.println("Server error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // Loads server's X.509 certificate from a PEM file
    private static X509Certificate loadCertificate(String filename) throws Exception {
        FileInputStream fis = new FileInputStream(filename);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
        fis.close();
        return cert;
    }

    // Loads server's private key from a PEM file
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

    // Sends file to client with AES encryption and a single HMAC-SHA1 for the entire file
    private static void sendFile(String filename, ObjectOutputStream out,
                                 SecretKey encKey, SecretKey macKey) throws Exception {
        File file = new File(filename);
        byte[] fileData = Files.readAllBytes(file.toPath()); // Read entire file
        // Initialize AES cipher with explicit padding mode
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, encKey);
        // Encrypt the entire file in one go
        byte[] encryptedData = cipher.doFinal(fileData);

        // Compute MAC for the entire encrypted data
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(macKey);
        byte[] macValue = mac.doFinal(encryptedData);

        // Send encrypted data and MAC
        out.writeObject(encryptedData);
        out.writeObject(macValue);
        out.flush();
    }
}