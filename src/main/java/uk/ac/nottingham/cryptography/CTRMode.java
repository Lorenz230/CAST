package uk.ac.nottingham.cryptography;

/**
 * Implementation of CipherMode that performs encryption and decryption
 * using Counter mode (CTR) with an underlying Cipher.
 * <br/>
 * This class is TWO of TWO primary code files in which you can complete
 * your solution to the coursework.
 */
public class CTRMode extends CipherMode {

    private Cipher cipher;
    private byte[] nonce;
    private long counter;
    private byte[] keystream = new byte[24];
    private int keystreamIndex = 24;

    public CTRMode() {
        super();
    }

    @Override
    public void initialise(Cipher cipher, byte[] key, byte[] nonce) {
        // Add your code here
        this.cipher = cipher;
        this.nonce = nonce.clone(); // defensive copy
        this.counter = 0;
        this.keystreamIndex = 24; // start with empty keystream
        cipher.initialise(key);
    }

    @Override
    public void encrypt(byte[] data) {
        // Add your code here
        for (int i = 0; i < data.length; i++) {
            if (keystreamIndex == 24) {
                byte[] inputBlock = new byte[24];
                System.arraycopy(nonce, 0, inputBlock, 0, 16);

                for (int j = 0; j < 8; j++) {
                    inputBlock[16 + j] = (byte) ((counter >>> (56 - 8 * j)) & 0xFF);
                }

                cipher.encrypt(inputBlock);
                System.arraycopy(inputBlock, 0, keystream, 0, 24);
                keystreamIndex = 0;
                counter++;
            }

            data[i] ^= keystream[keystreamIndex++];
        }
    }

    @Override
    public void decrypt(byte[] data) {
        // Add your code here;
        encrypt(data); // symmetric under XOR
    }


    @Override
    public void seek(byte[] counter) {
        // Add your code here
        long value = 0;
        int padding = 8 - counter.length;

        for (int i = 0; i < padding; i++) {
            value <<= 8;
        }

        for (byte b : counter) {
            value = (value << 8) | (b & 0xFF);
        }

        this.counter = value;
        this.keystreamIndex = 24; // invalidate current keystream
    }
}
