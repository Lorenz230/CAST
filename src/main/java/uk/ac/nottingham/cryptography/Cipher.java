package uk.ac.nottingham.cryptography;

/**
 * Abstract class that defines a Cipher. This class is extended by CASTCipher,
 * and is used primarily within the CipherMode class.
 * <br/>
 * Do not edit this class file.
 */
public abstract class Cipher {
    private final int blockLength;

    public int getBlockLength() {
        return blockLength;
    }

    private final int keyLength;

    public int getKeyLength() {
        return keyLength;
    }

    public Cipher(int blockLength, int keyLength) {
        this.blockLength = blockLength;
        this.keyLength = keyLength;
    }

    public abstract void initialise(byte[] key);

    public abstract void encrypt(byte[] data);

    public abstract void decrypt(byte[] data);

}
