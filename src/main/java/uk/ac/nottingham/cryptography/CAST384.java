package uk.ac.nottingham.cryptography;

/**
 * Implementation of CASTCipher that encrypts and decrypts using the
 * CAST-384 algorithm.
 * <br/>
 * This class is ONE of TWO primary code files in which you can complete
 * your solution to the coursework.
 */
public class CAST384 extends CASTCipher {

    public CAST384() {
        super(192, 384);
    }

    @Override
    public void initialise(byte[] key) {
        // Add your code here
    }

    @Override
    public CASTKeySet generateScheduleKeys(int roundCount, int dodecadCount) {
        // Add your code here
        return new CASTKeySet(null, null);
    }

    @Override
    public CASTKeySet generateRoundKeys(CASTKeySet T, byte[] key, int roundCount, int dodecadCount) {
        // Add your code here
        return new CASTKeySet(null, null);
    }

    @Override
    public int f1 (int d, int Km, int Kr) {
        // Add your code here
        return 0;
    }

    @Override
    public int f2 (int d, int Km, int Kr) {
        // Add your code here
        return 0;
    }

    @Override
    public int f3 (int d, int Km, int Kr) {
        // Add your code here
        return 0;
    }

    @Override
    public int f4 (int d, int Km, int Kr) {
        // Add your code here
        return 0;
    }

    @Override
    public int f5 (int d, int Km, int Kr) {
        // Add your code here
        return 0;
    }

    @Override
    public int f6 (int d, int Km, int Kr) {
        // Add your code here
        return 0;
    }

    @Override
    public void dodecad(int[] block, int[] Tm, int[] Tr, int idx) {
        // Add your code here
    }

    @Override
    public void hexad(int[] block, int[] Km, int[] Kr, int idx) {
        // Add your code here
    }

    @Override
    public void hexadInv(int[] block, int[] Km, int[] Kr, int idx) {
        // Add your code here
    }

    @Override
    public void encrypt(byte[] data) {
        // Add your code here
    }

    @Override
    public void decrypt(byte[] data) {
        // Add your code here
    }

}
