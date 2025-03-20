# Diffie-Hellman Key Exchange Implementation
This program demonstrates a Diffie-Hellman key exchange between a client (Alice) and server (Bob) using TCP sockets.

## Files Included
- Server.java - Server (Bob) implementation
- Client.java - Client (Alice) implementation  
- server_output.txt - Output from server execution
- client_output.txt - Output from client execution
- README.md - This documentation file

## Parameters Used
- g = 1907 (generator)
- p = 784313 (prime modulus)
- SA = 160031 (Alice's secret)
- SB = 12077 (Bob's secret)

## Compilation Instructions
1. Make sure Java Development Kit (JDK) is installed
2. Navigate to the directory containing the source files
3. Compile both programs:
```bash
javac Server.java
javac Client.java
```

## Execution Instructions
1. Open two terminal windows
2. In the first terminal, start the Server:
```bash
java Server
```
3. Wait until you see "Server is waiting for client..."
4. In the second terminal, start the Client:  
```bash
java Client
```

## Expected Output
Server output:
```
Server started on port: 5002
Server is waiting for client...
Client connected!
Received from Alice (A): 179464
Sending to Alice (B): 449485
Shared Key: 475269
```

Client output:
```
Connected to server on port: 5002
Sending to Bob (A): 179464
Received from Bob (B): 449485
Shared Key: 475269
```

## Troubleshooting
- If "Address already in use" error occurs:
  1. Wait a few moments and try again
  2. Or try restarting the terminals
  3. Or restart the computer
- Make sure to start Server before Client
- Verify both programs are using the same port number
