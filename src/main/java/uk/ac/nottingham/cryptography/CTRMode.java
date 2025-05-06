package uk.ac.nottingham.cryptography;

/**
 * Implementation of CipherMode that performs encryption and decryption
 * using Counter mode (CTR) with an underlying Cipher.
 * <br/>
 * This class is TWO of TWO primary code files in which you can complete
 * your solution to the coursework.
 */
public class CTRMode extends CipherMode {

    public CTRMode() {
        super();
    }

    @Override
    public void initialise(Cipher cipher, byte[] key, byte[] nonce) {
        // Add your code here
    }

    @Override
    public void encrypt(byte[] data) {
        // Add your code here
    }

    @Override
    public void decrypt(byte[] data) {
        // Add your code here;
    }

    @Override
    public void seek(byte[] counter) {
        // Add your code here
    }
}
