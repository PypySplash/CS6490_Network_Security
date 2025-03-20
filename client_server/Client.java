import java.io.*;
import java.net.*;
import java.math.BigInteger;

public class Client {
    static final BigInteger g = new BigInteger("1907");
    static final BigInteger p = new BigInteger("784313");
    static final BigInteger SA = new BigInteger("160031");
    
    public static void main(String[] args) {
        Socket socket = null;
        DataInputStream in = null;
        DataOutputStream out = null;
        
        try {
            // Try to connect to the same port as server
            int port = 5002;
            socket = new Socket("localhost", port);
            System.out.println("Connected to server on port: " + port);

            in = new DataInputStream(socket.getInputStream());
            out = new DataOutputStream(socket.getOutputStream());

            BigInteger A = g.modPow(SA, p);
            System.out.println("Sending to Bob (A): " + A);
            out.writeUTF(A.toString());

            String receivedB = in.readUTF();
            BigInteger B = new BigInteger(receivedB);
            System.out.println("Received from Bob (B): " + B);

            BigInteger K = B.modPow(SA, p);
            System.out.println("Shared Key: " + K);

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (out != null) out.close();
                if (in != null) in.close();
                if (socket != null) socket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}