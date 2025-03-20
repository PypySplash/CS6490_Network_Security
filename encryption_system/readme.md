# Encryption System Documentation

This program implements a secure encryption system based on substitution-permutation networks, featuring a 64-bit key and multiple rounds of encryption for enhanced security.

## System Requirements

The encryption system has been designed and tested to run in the CADE lab environment with the following specifications:

- Java Runtime Environment (JRE) 8 or higher
- Operating System: Linux (CADE lab machines)

## Installation and Execution Instructions

To successfully compile and run the encryption system on CADE lab machines, please follow these steps in order:

1. First, copy the source code file to your working directory:
   ```bash
   cp EncryptionSystem.java ~/your_working_directory/
   ```

2. Navigate to your working directory:
   ```bash
   cd ~/your_working_directory/
   ```

3. Compile the Java source code:
   ```bash
   javac EncryptionSystem.java
   ```

4. Execute the compiled program:
   ```bash
   java EncryptionSystem
   ```

## Output Description

Upon successful execution, the program generates an output file named `encryption_output.txt` in the current directory. This file contains comprehensive information about the encryption and decryption processes, including:

- Original input data in hexadecimal format
- Detailed round-by-round encryption results
- Final encrypted output
- Round-by-round decryption process
- Final decrypted result matching the original input
- Additional test case with a single bit modification

## Important Notes

Before running the program, please ensure:

1. You have appropriate write permissions in the current directory
2. The Java version installed meets the minimum requirements
3. All operations are performed on a CADE lab machine for guaranteed compatibility

## Troubleshooting

If you encounter any issues during execution:

1. Verify your Java version using `java -version`
2. Ensure all file permissions are correctly set
3. Confirm you are working on a CADE lab machine

## Program Structure

The encryption system implements:
- 8 unique substitution tables
- 16 rounds of encryption/decryption
- 64-bit key derived from an 8-character password
- Left/right circular bit shifts for permutation
- Comprehensive input validation and error handling

For additional technical details or assistance, please refer to the source code documentation.