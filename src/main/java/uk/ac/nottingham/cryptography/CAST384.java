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
        // generate temporary schedule constants
        CASTKeySet tempKeys = generateScheduleKeys(12, 4);

        // generate round keys
        CASTKeySet roundKeys = generateRoundKeys(tempKeys, key, 12, 4);
        this.K = roundKeys;
    }

    @Override
    public CASTKeySet generateScheduleKeys(int roundCount, int dodecadCount) {
        int total = roundCount * dodecadCount;
        int[] Tm = new int[12 * total]; // masking key constants
        int[] Tr = new int[12 * total]; // rotation key constants

        int cm = 0x5A827999;
        int dm = 0x6ED9EBA1;
        int cr = 19;
        int dr = 17;

        for (int i = 0; i < total; i++) {
            for (int j = 0; j < 12; j++) {
                int idx = i * 12 + j;
                Tm[idx] = cm;
                cm = cm + dm;
                Tr[idx] = cr % 32;
                cr = cr + dr;
            }
        }

        return new CASTKeySet(Tm, Tr);
    }

    @Override
    public CASTKeySet generateRoundKeys(CASTKeySet T, byte[] key, int roundCount, int dodecadCount) {
        int[] block = new int[12];

        // convert the key bytes into 32 bit words
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

        // retrieve arrays of temporary masking and rotation constants
        int[] Tm = T.getM();
        int[] Tr = T.getR();

        int[] Km = new int[roundCount * 6];
        int[] Kr = new int[roundCount * 6];


        // apply dodecad function multiple times
        for (int i = 0; i < roundCount; i++) {
            for (int d = 0; d < dodecadCount; d++) {
                int idx = (i * dodecadCount + d) * 12;
                dodecad(block, Tm, Tr, idx);
            }

            int base = i * 6;

            // get masking keys from transformed block
            Km[base + 0] = block[11];
            Km[base + 1] = block[9];
            Km[base + 2] = block[7];
            Km[base + 3] = block[5];
            Km[base + 4] = block[3];
            Km[base + 5] = block[1];

            Kr[base + 0] = block[0] & 31;
            Kr[base + 1] = block[2] & 31;
            Kr[base + 2] = block[4] & 31;
            Kr[base + 3] = block[6] & 31;
            Kr[base + 4] = block[8] & 31;
            Kr[base + 5] = block[10] & 31;
        }

        return new CASTKeySet(Km, Kr);
    }

    @Override
    public int f1 (int d, int Km, int Kr) {
        // mask input with km and rotate left by kr bits
        int I = Integer.rotateLeft(Km + d, Kr);

        // split I into four bytes
        int I1 = (I >>> 24) & 0xFF;
        int I2 = (I >>> 16) & 0xFF;
        int I3 = (I >>> 8) & 0xFF;
        int I4 = I & 0xFF;

        // combine outputs using F1 operation order
        return ((S1[I1] ^ S2[I2]) - S3[I3]) + S4[I4];
    }

    @Override
    public int f2 (int d, int Km, int Kr) {
        int I = Integer.rotateLeft(Km ^ d, Kr);
        int I1 = (I >>> 24) & 0xFF;
        int I2 = (I >>> 16) & 0xFF;
        int I3 = (I >>> 8) & 0xFF;
        int I4 = I & 0xFF;

        // combine outputs using the F2 operation order
        return ((S1[I1] - S2[I2]) + S3[I3]) ^ S4[I4];
    }

    @Override
    public int f3 (int d, int Km, int Kr) {
        int I = Integer.rotateLeft(Km - d, Kr);
        int I1 = (I >>> 24) & 0xFF;
        int I2 = (I >>> 16) & 0xFF;
        int I3 = (I >>> 8) & 0xFF;
        int I4 = I & 0xFF;

        // combine outputs using the F3 operation order
        return ((S1[I1] + S2[I2]) ^ S3[I3]) - S4[I4];
    }

    @Override
    public int f4 (int d, int Km, int Kr) {
        int I = Integer.rotateLeft(Km - d, Kr);
        int I1 = (I >>> 24) & 0xFF;
        int I2 = (I >>> 16) & 0xFF;
        int I3 = (I >>> 8) & 0xFF;
        int I4 = I & 0xFF;

        // combine outputs using F4 operation order
        return ((S1[I1] ^ S2[I2]) + S3[I3]) - S4[I4];
    }

    @Override
    public int f5 (int d, int Km, int Kr) {
        int I = Integer.rotateLeft(Km + d, Kr);
        int I1 = (I >>> 24) & 0xFF;
        int I2 = (I >>> 16) & 0xFF;
        int I3 = (I >>> 8) & 0xFF;
        int I4 = I & 0xFF;

        // combine outputs usign F5 operation order
        return ((S1[I1] - S2[I2]) ^ S3[I3]) + S4[I4];
    }

    @Override
    public int f6 (int d, int Km, int Kr) {
        int I = Integer.rotateLeft(Km ^ d, Kr);
        int I1 = (I >>> 24) & 0xFF;
        int I2 = (I >>> 16) & 0xFF;
        int I3 = (I >>> 8) & 0xFF;
        int I4 = I & 0xFF;

        // combine output using F6 operation order
        return ((S1[I1] + S2[I2]) - S3[I3]) ^ S4[I4];
    }

    @Override
    public void dodecad(int[] block, int[] Tm, int[] Tr, int idx) {
        // apply 12 chained F-functions on the 384-bit key block
        block[10] ^= f1(block[11], Tm[idx + 0], Tr[idx + 0]);
        block[9]  ^= f2(block[10], Tm[idx + 1], Tr[idx + 1]);
        block[8]  ^= f3(block[9],  Tm[idx + 2], Tr[idx + 2]);
        block[7]  ^= f4(block[8],  Tm[idx + 3], Tr[idx + 3]);
        block[6]  ^= f5(block[7],  Tm[idx + 4], Tr[idx + 4]);
        block[5]  ^= f6(block[6],  Tm[idx + 5], Tr[idx + 5]);
        block[4]  ^= f1(block[5],  Tm[idx + 6], Tr[idx + 6]);
        block[3]  ^= f2(block[4],  Tm[idx + 7], Tr[idx + 7]);
        block[2]  ^= f3(block[3],  Tm[idx + 8], Tr[idx + 8]);
        block[1]  ^= f4(block[2],  Tm[idx + 9], Tr[idx + 9]);
        block[0]  ^= f5(block[1],  Tm[idx +10], Tr[idx +10]);
        block[11] ^= f6(block[0],  Tm[idx +11], Tr[idx +11]);
    }

    @Override
    public void hexad(int[] block, int[] Km, int[] Kr, int idx) {
        // Apply one full hexad round over the 6 × 32-bit block

        int A = block[0];
        int B = block[1];
        int C = block[2];
        int D = block[3];
        int E = block[4];
        int F = block[5];

        int t1 = f1(F, Km[idx + 0], Kr[idx + 0]);
        E ^= t1; // F1(F) -> E

        int t2 = f2(E, Km[idx + 1], Kr[idx + 1]);
        D ^= t2; // F2(E) -> D

        int t3 = f3(D, Km[idx + 2], Kr[idx + 2]);
        C ^= t3; // F3(D) -> C

        int t4 = f4(C, Km[idx + 3], Kr[idx + 3]);
        B ^= t4; // F4(C) -> B

        int t5 = f5(B, Km[idx + 4], Kr[idx + 4]);
        A ^= t5; // F5(B) -> A

        int t6 = f6(A, Km[idx + 5], Kr[idx + 5]);
        F ^= t6; // F6(A) -> F

        // update block with new values after hexad
        block[0] = A;
        block[1] = B;
        block[2] = C;
        block[3] = D;
        block[4] = E;
        block[5] = F;
    }

    @Override
    public void hexadInv(int[] block, int[] Km, int[] Kr, int idx) {
        int A = block[0];
        int B = block[1];
        int C = block[2];
        int D = block[3];
        int E = block[4];
        int F = block[5];

        // apply the inverse of hexad
        int t6 = f6(A, Km[idx + 5], Kr[idx + 5]);
        F ^= t6;

        int t5 = f5(B, Km[idx + 4], Kr[idx + 4]);
        A ^= t5;

        int t4 = f4(C, Km[idx + 3], Kr[idx + 3]);
        B ^= t4;

        int t3 = f3(D, Km[idx + 2], Kr[idx + 2]);
        C ^= t3;

        int t2 = f2(E, Km[idx + 1], Kr[idx + 1]);
        D ^= t2;

        int t1 = f1(F, Km[idx + 0], Kr[idx + 0]);
        E ^= t1;

        // store updates values back into the block
        block[0] = A;
        block[1] = B;
        block[2] = C;
        block[3] = D;
        block[4] = E;
        block[5] = F;
    }

    @Override
    public void encrypt(byte[] data) {
        int[] block = new int[6];
        for (int i = 0; i < 6; i++) {
            int index = i * 4;
            block[i] = ((data[index] & 0xFF) << 24) |
                    ((data[index + 1] & 0xFF) << 16) |
                    ((data[index + 2] & 0xFF) << 8) |
                    (data[index + 3] & 0xFF);
        }

        // apply 6 forward hexad rounds
        // each uses a set of 6 key pairs
        for (int i = 0; i < 6; i++) {
            hexad(block, K.getM(), K.getR(), i * 6);
        }

        // apply 6 inverse hexad rounds
        for (int i = 6; i < 12; i++) {
            hexadInv(block, K.getM(), K.getR(), i * 6);
        }

        for (int i = 0; i < 6; i++) {
            int index = i * 4;
            data[index]     = (byte) (block[i] >>> 24);
            data[index + 1] = (byte) (block[i] >>> 16);
            data[index + 2] = (byte) (block[i] >>> 8);
            data[index + 3] = (byte) (block[i]);
        }
    }

    @Override
    public void decrypt(byte[] data) {
        int[] block = new int[6];
        for (int i = 0; i < 6; i++) {
            int index = i * 4;
            block[i] = ((data[index] & 0xFF) << 24) |
                    ((data[index + 1] & 0xFF) << 16) |
                    ((data[index + 2] & 0xFF) << 8) |
                    (data[index + 3] & 0xFF);
        }

        // apply 6 forward hexad rounds in reverse
        for (int i = 11; i >= 6; i--) {
            hexad(block, K.getM(), K.getR(), i * 6);
        }

        // apply 6 inverse hexad rounds in reverse
        for (int i = 5; i >= 0; i--) {
            hexadInv(block, K.getM(), K.getR(), i * 6);
        }

        for (int i = 0; i < 6; i++) {
            int index = i * 4;
            data[index]     = (byte) (block[i] >>> 24);
            data[index + 1] = (byte) (block[i] >>> 16);
            data[index + 2] = (byte) (block[i] >>> 8);
            data[index + 3] = (byte) (block[i]);
        }
    }

}
