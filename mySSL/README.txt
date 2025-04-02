Programming Assignment 2: Custom SSL Implementation
Author: Huang Yuanyu
Date: March 28, 2025

Overview
--------
This project implements a custom SSL-like protocol in Java, featuring a handshake phase for mutual authentication and key exchange, followed by a data phase for secure file transfer. The server and client use self-signed certificates for authentication, exchange nonces to generate a master secret, and derive symmetric keys for AES encryption and HMAC-SHA1 integrity protection. A 50 KB file (sample.txt) is transferred from the server to the client, decrypted, and verified.

Files
-----
- mySSLServer.java: Server-side implementation of the custom SSL protocol.
- mySSLClient.java: Client-side implementation of the custom SSL protocol.
- sample.txt: A 50 KB file containing random data, generated for testing.
- received.txt: The file received and decrypted by the client.
- client_cert.pem, client_key.pem: Client's certificate and private key.
- server_cert.pem, server_key.pem: Server's certificate and private key.

Certificate Generation
----------------------
The certificates and private keys were generated using OpenSSL with the following commands:

1. Generate server certificate and private key:
   openssl req -x509 -newkey rsa:2048 -keyout server_key.pem -out server_cert.pem -days 365 -nodes
   - Subject: CN=Server

2. Generate client certificate and private key:
   openssl req -x509 -newkey rsa:2048 -keyout client_key.pem -out client_cert.pem -days 365 -nodes
   - Subject: CN=Client

These commands create self-signed certificates valid for 365 days, with RSA keys of 2048 bits and no passphrase (-nodes).

Sample File Generation
----------------------
The sample.txt file (50 KB) was generated with random data using:
   dd if=/dev/urandom of=sample.txt bs=1024 count=50

Compilation and Execution
-------------------------
1. Compile the Java files:
   javac mySSLServer.java mySSLClient.java

2. Run the server in one terminal:
   java mySSLServer

3. Run the client in another terminal:
   java mySSLClient

Ensure all required files (sample.txt, *.pem) are in the same directory as the compiled classes.

Testing Environment
-------------------
The program was tested on a MacBook Pro (macOS) and is expected to work on CADE Lab machines with a Java Development Kit (JDK) installed. The output examples below were recorded locally.

Output Examples
---------------
1. Successful Execution:
   - Server output:
     Server started on port 8443
     New client connected
     Handshake verification successful
     File transfer completed successfully

   - Client output:
     Connected to server
     Handshake verification successful
     File received successfully
     File verification successful

   After running, verify file consistency:
     cmp sample.txt received.txt
   (No output indicates the files are identical.)

2. Failed Handshake (example with modified client hash):
   - Modify mySSLClient.java line ~80 to use "CLIENT2" instead of "CLIENT":
     byte[] hash = computeKeyedHash(allMessages, masterSecret, "CLIENT2");
   - Recompile and run:
     javac mySSLClient.java
     java mySSLServer
     java mySSLClient

   - Server output:
     Server started on port 8443
     New client connected
     Handshake verification failed!

   - Client output:
     Connected to server
     Handshake verification failed!

Notes
-----
- The program uses AES/ECB/PKCS5Padding for encryption and HMAC-SHA1 for integrity protection.
- The handshake phase includes mutual authentication, nonce exchange, and hash verification.
- The data phase encrypts and transfers the entire file at once, with a single MAC for integrity.
- Error handling is implemented for connection issues, file I/O, and cryptographic operations.
