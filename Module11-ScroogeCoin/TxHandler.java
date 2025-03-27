import java.util.ArrayList;
import java.util.HashSet;



public class TxHandler {
	private UTXOPool utxoPool;
	/* Creates a public ledger whose current UTXOPool (collection of unspent 
	 * transaction outputs) is utxoPool. This should make a defensive copy of 
	 * utxoPool by using the UTXOPool(UTXOPool uPool) constructor.
	 */
	public TxHandler(UTXOPool utxoPool) {
		// IMPLEMENT THIS
		this.utxoPool = new UTXOPool(utxoPool);
	}

	/* Returns true if 
	 * (1) all outputs claimed by tx are in the current UTXO pool, 
	 * (2) the signatures on each input of tx are valid, 
	 * (3) no UTXO is claimed multiple times by tx, 
	 * (4) all of tx’s output values are non-negative, and
	 * (5) the sum of tx’s input values is greater than or equal to the sum of   
	        its output values;
	   and false otherwise.
	 */

	public boolean isValidTx(Transaction tx) {
		// IMPLEMENT THIS
		HashSet<UTXO> claimedUTXOs = new HashSet<>();
        double inputSum = 0.0;
        double outputSum = 0.0;

        // Check inputs
        for (int i = 0; i < tx.numInputs(); i++) {
            Transaction.Input input = tx.getInput(i);
            UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);

            // (1) Check if the claimed output is in the UTXO pool
            if (!utxoPool.contains(utxo)) {
                return false;
            }

            // (3) Check for double-spending within this transaction
            if (claimedUTXOs.contains(utxo)) {
                return false;
            }
            claimedUTXOs.add(utxo);

            // (2) Verify signature
            Transaction.Output prevOutput = utxoPool.getTxOutput(utxo);
            RSAKey pubKey = prevOutput.address;
            byte[] message = tx.getRawDataToSign(i);
            byte[] signature = input.signature;
            if (!pubKey.verifySignature(message, signature)) {
                return false;
            }

            // Accumulate input value
            inputSum += prevOutput.value;
        }

        // Check outputs
        for (Transaction.Output output : tx.getOutputs()) {
            // (4) Check if output values are non-negative
            if (output.value < 0) {
                return false;
            }
            outputSum += output.value;
        }

        // (5) Check if input sum is >= output sum
        return inputSum >= outputSum;
	}

	/* Handles each epoch by receiving an unordered array of proposed 
	 * transactions, checking each transaction for correctness, 
	 * returning a mutually valid array of accepted transactions, 
	 * and updating the current UTXO pool as appropriate.
	 */
	public Transaction[] handleTxs(Transaction[] possibleTxs) {
		// IMPLEMENT THIS
		if (possibleTxs == null) {
            return new Transaction[0];
        }

        ArrayList<Transaction> acceptedTxs = new ArrayList<>();
        boolean modified;

        // Iteratively process transactions until no more can be added
        do {
            modified = false;
            for (Transaction tx : possibleTxs) {
                if (!acceptedTxs.contains(tx) && isValidTx(tx)) {
                    // Add transaction to accepted list
                    acceptedTxs.add(tx);

                    // Update UTXO pool: remove spent UTXOs
                    for (int i = 0; i < tx.numInputs(); i++) {
                        Transaction.Input input = tx.getInput(i);
                        UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);
                        utxoPool.removeUTXO(utxo);
                    }

                    // Add new UTXOs from this transaction
                    byte[] txHash = tx.getHash();
                    for (int i = 0; i < tx.numOutputs(); i++) {
                        UTXO utxo = new UTXO(txHash, i);
                        utxoPool.addUTXO(utxo, tx.getOutput(i));
                    }

                    modified = true;
                }
            }
        } while (modified); // Continue until no more transactions can be added

        // Convert ArrayList to array and return
        return acceptedTxs.toArray(new Transaction[0]);
	}
} 
