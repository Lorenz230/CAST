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
        int total = roundCount * dodecadCount; // total number of dodecads
        int[] Tm = new int[12 * total];
        int[] Tr = new int[12 * total];

        int cm = 0x5A827999;
        int dm = 0x6ED9EBA1;
        int cr = 19;
        int dr = 17;

        for (int i = 0; i < total; i++) {
            for (int j = 0; j < 12; j++) {
                int idx = i * 12 + j;
                Tm[idx] = cm;
                cm = cm + dm; // modulo 2^32 wrap-around is handled by Java automatically
                Tr[idx] = cr % 32;
                cr = cr + dr;
            }
        }

        return new CASTKeySet(Tm, Tr);
    }

    @Override
    public CASTKeySet generateRoundKeys(CASTKeySet T, byte[] key, int roundCount, int dodecadCount) {
        // Add your code here
        int[] block = new int[12];

        for (int i = 0; i < 12; i++) {
            int index = i * 4;
            if (index + 3 < key.length) {
                block[i] = ((key[index] & 0xFF) << 24)
                        | ((key[index + 1] & 0xFF) << 16)
                        | ((key[index + 2] & 0xFF) << 8)
                        | (key[index + 3] & 0xFF);
            } else {
                block[i] = 0;
            }
        }

        int[] Tm = T.getM();
        int[] Tr = T.getR();

        int[] Km = new int[roundCount * 6];
        int[] Kr = new int[roundCount * 6];

        for (int i = 0; i < roundCount; i++) {
            for (int d = 0; d < dodecadCount; d++) {
                int idx = (i * dodecadCount + d) * 12;
                dodecad(block, Tm, Tr, idx);
            }

            int base = i * 6;

            Km[base + 0] = block[11];       // L
            Km[base + 1] = block[9];        // J
            Km[base + 2] = block[7];        // H
            Km[base + 3] = block[5];        // F
            Km[base + 4] = block[3];        // D
            Km[base + 5] = block[1];        // B

            Kr[base + 0] = block[0] & 31;   // A % 32
            Kr[base + 1] = block[2] & 31;   // C % 32
            Kr[base + 2] = block[4] & 31;   // E % 32
            Kr[base + 3] = block[6] & 31;   // G % 32
            Kr[base + 4] = block[8] & 31;   // I % 32
            Kr[base + 5] = block[10] & 31;  // K % 32
        }

        return new CASTKeySet(Km, Kr);
    }

    @Override
    public int f1 (int d, int Km, int Kr) {
        // Add your code here
        int I = Integer.rotateLeft(Km + d, Kr);
        int I1 = (I >>> 24) & 0xFF;
        int I2 = (I >>> 16) & 0xFF;
        int I3 = (I >>> 8) & 0xFF;
        int I4 = I & 0xFF;
        return ((S1[I1] ^ S2[I2]) - S3[I3]) + S4[I4];
    }

    @Override
    public int f2 (int d, int Km, int Kr) {
        // Add your code here
        int I = Integer.rotateLeft(Km ^ d, Kr);
        int I1 = (I >>> 24) & 0xFF;
        int I2 = (I >>> 16) & 0xFF;
        int I3 = (I >>> 8) & 0xFF;
        int I4 = I & 0xFF;
        return ((S1[I1] - S2[I2]) + S3[I3]) ^ S4[I4];
    }

    @Override
    public int f3 (int d, int Km, int Kr) {
        // Add your code here
        int I = Integer.rotateLeft(Km - d, Kr);
        int I1 = (I >>> 24) & 0xFF;
        int I2 = (I >>> 16) & 0xFF;
        int I3 = (I >>> 8) & 0xFF;
        int I4 = I & 0xFF;
        return ((S1[I1] + S2[I2]) ^ S3[I3]) - S4[I4];
    }

    @Override
    public int f4 (int d, int Km, int Kr) {
        // Add your code here
        int I = Integer.rotateLeft(Km - d, Kr);
        int I1 = (I >>> 24) & 0xFF;
        int I2 = (I >>> 16) & 0xFF;
        int I3 = (I >>> 8) & 0xFF;
        int I4 = I & 0xFF;
        return ((S1[I1] ^ S2[I2]) + S3[I3]) - S4[I4];
    }

    @Override
    public int f5 (int d, int Km, int Kr) {
        // Add your code here
        int I = Integer.rotateLeft(Km + d, Kr);
        int I1 = (I >>> 24) & 0xFF;
        int I2 = (I >>> 16) & 0xFF;
        int I3 = (I >>> 8) & 0xFF;
        int I4 = I & 0xFF;
        return ((S1[I1] - S2[I2]) ^ S3[I3]) + S4[I4];
    }

    @Override
    public int f6 (int d, int Km, int Kr) {
        int I = Integer.rotateLeft(Km ^ d, Kr);
        int I1 = (I >>> 24) & 0xFF;
        int I2 = (I >>> 16) & 0xFF;
        int I3 = (I >>> 8) & 0xFF;
        int I4 = I & 0xFF;
        return ((S1[I1] + S2[I2]) - S3[I3]) ^ S4[I4];
    }

    @Override
    public void dodecad(int[] block, int[] Tm, int[] Tr, int idx) {
        // Add your code here
        int base = idx;

        block[10] ^= f1(block[11], Tm[base + 0], Tr[base + 0]);
        block[9]  ^= f2(block[10], Tm[base + 1], Tr[base + 1]);
        block[8]  ^= f3(block[9],  Tm[base + 2], Tr[base + 2]);
        block[7]  ^= f4(block[8],  Tm[base + 3], Tr[base + 3]);
        block[6]  ^= f5(block[7],  Tm[base + 4], Tr[base + 4]);
        block[5]  ^= f6(block[6],  Tm[base + 5], Tr[base + 5]);
        block[4]  ^= f1(block[5],  Tm[base + 6], Tr[base + 6]);
        block[3]  ^= f2(block[4],  Tm[base + 7], Tr[base + 7]);
        block[2]  ^= f3(block[3],  Tm[base + 8], Tr[base + 8]);
        block[1]  ^= f4(block[2],  Tm[base + 9], Tr[base + 9]);
        block[0]  ^= f5(block[1],  Tm[base +10], Tr[base +10]);
        block[11] ^= f6(block[0],  Tm[base +11], Tr[base +11]);
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
