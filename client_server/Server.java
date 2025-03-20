import java.io.*;
import java.net.*;
import java.math.BigInteger;

public class Server {
    static final BigInteger g = new BigInteger("1907");
    static final BigInteger p = new BigInteger("784313");
    static final BigInteger SB = new BigInteger("12077");
    
    public static void main(String[] args) {
        ServerSocket serverSocket = null;
        Socket socket = null;
        DataInputStream in = null;
        DataOutputStream out = null;
        
        try {
            // Try different ports if one is busy
            int port = 5002;
            boolean connected = false;
            while (!connected && port < 5010) {
                try {
                    serverSocket = new ServerSocket(port);
                    connected = true;
                    System.out.println("Server started on port: " + port);
                } catch (IOException e) {
                    port++;
                }
            }
            
            if (!connected) {
                System.out.println("Could not find available port. Exiting...");
                return;
            }
            
            System.out.println("Server is waiting for client...");
            socket = serverSocket.accept();
            System.out.println("Client connected!");

            in = new DataInputStream(socket.getInputStream());
            out = new DataOutputStream(socket.getOutputStream());

            String receivedA = in.readUTF();
            BigInteger A = new BigInteger(receivedA);
            System.out.println("Received from Alice (A): " + A);

            BigInteger B = g.modPow(SB, p);
            System.out.println("Sending to Alice (B): " + B);
            out.writeUTF(B.toString());

            BigInteger K = A.modPow(SB, p);
            System.out.println("Shared Key: " + K);

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (out != null) out.close();
                if (in != null) in.close();
                if (socket != null) socket.close();
                if (serverSocket != null) serverSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}