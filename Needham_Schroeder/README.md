# Programming Assignment 1 - Needham-Schroeder Protocol

## Project Structure
- KDC.java: Implements the Key Distribution Center, generating shared keys and issuing session keys/tickets.
- Alice.java: Implements Alice's client, initiating the authentication protocol with KDC and Bob.
- Bob.java: Implements Bob's client, verifying Alice's request and completing mutual authentication.
- ReflectionAttack.java: Demonstrates the reflection attack in ECB mode and its prevention in CBC mode.

## Compilation and Running on CADE Lab Machines
1. Compile all files:
   javac *.java
2. Run the extended protocol:
   java Alice
3. Run the reflection attack demonstration:
   java ReflectionAttack

## Requirements
- Java 8 or higher
- No external libraries required beyond standard Java crypto packages

## Notes
- The program uses 3DES with 64-bit nonces as specified.
- All outputs are in hexadecimal format for debugging and verification.
- The reflection attack assumes Trudy knows the ticket, as per assignment instructions.
- ECB mode demonstrates the reflection attack vulnerability, while CBC mode shows its prevention with different outputs for the last two messages.

## Sample Output
### java Alice
Generated nonce: 61d0043d98128c84
Encrypted request to KDC: be642ca4f73f767bfc26a4d036fac69f9d6d1ff1d1891e8e9cf1dab2e536ec1c
[... additional lines ...]
Authentication successful!
Received nonce: 61d0043d98128c84
Sending response: 61d0043d98128c83

### java ReflectionAttack
Alice's encrypted nonce (ECB): 7b5c7f9cc759dc1d89efa8c62dda4620
Trudy replays message to Bob: 7b5c7f9cc759dc1d89efa8c62dda4620
[... additional lines ...]
Trudy recovers nonce - 1 (attack succeeds): 80b8d1861151c319
Alice's encrypted nonce (CBC): b01ea0b4811c9f97a465a96fe0f6ee38
Bob's encrypted response (CBC): a4e8bdb75e7953eb3c919acda8443995
Decrypted nonce with wrong IV (garbage): 87696827cfe71210