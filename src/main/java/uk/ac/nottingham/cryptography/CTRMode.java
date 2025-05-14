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
        // store cipher and nonce, reset counter ad keystream
        this.cipher = cipher;
        this.nonce = nonce.clone();
        this.counter = 0;
        this.keystreamIndex = 24;

        // initialise block cipher with key
        cipher.initialise(key);
    }

    @Override
    public void encrypt(byte[] data) {
        for (int i = 0; i < data.length; i++) {
            if (keystreamIndex == 24) {
                byte[] inputBlock = new byte[24]; // generate new block
                System.arraycopy(nonce, 0, inputBlock, 0, 16); // copy nonce into first part of block

                // append 8-byte counter
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
        encrypt(data); // same as enctryption
    }


    @Override
    public void seek(byte[] counter) {
        long value = 0; // set internal counter
        int padding = 8 - counter.length;

        // pad zeros for shorter inputs
        for (int i = 0; i < padding; i++) {
            value <<= 8;
        }

        for (byte b : counter) {
            value = (value << 8) | (b & 0xFF);
        }

        this.counter = value;
        this.keystreamIndex = 24;
    }
}
