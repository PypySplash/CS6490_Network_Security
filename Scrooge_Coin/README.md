# ScroogeCoin Transaction Validator (CS6490 Module 11)

## Overview
This project implements a transaction validator for a simplified blockchain system called ScroogeCoin, as part of the CS6490 Network Security course. It validates transactions using the UTXO model and RSA signatures, ensuring no double-spending and correct transaction handling.

## Features
- Validates transaction inputs and outputs (non-negative values, input >= output).
- Verifies RSA signatures for transaction authenticity.
- Handles double-spending prevention using a UTXO pool.
- Processes interdependent transactions iteratively.

## Files
- `src/TxHandler.java`: Core implementation of transaction validation and handling.
- `src/Transaction.java`, `src/UTXO.java`, `src/UTXOPool.java`: Supporting classes provided by the course.

## Dependencies
- `rsa.jar`: RSA encryption library.
- `algs4.jar`: Algorithm utilities.
- `scroogeCoinGrader.jar`: Grading framework (not included).

## How to Run
1. Place all `.java` files in a directory with the required JARs.
2. Compile: `javac -cp scroogeCoinGrader.jar:rsa.jar:algs4.jar:. TestTxHandler.java`
3. Run: `java -cp scroogeCoinGrader.jar:rsa.jar:algs4.jar:. TestTxHandler`

## Results
Passed all 15 tests (7 for `isValidTx`, 8 for `handleTxs`).
