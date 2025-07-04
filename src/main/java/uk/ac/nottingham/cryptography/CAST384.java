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
        this.K = generateRoundKeys(tempKeys, key, 12, 4);
    }

    @Override
    public CASTKeySet generateScheduleKeys(int roundCount, int dodecadCount) {
        int totalIterations = roundCount * dodecadCount;
        int[] TempMaskKeys = new int[12 * totalIterations]; // masking key constants
        int[] tempRotationKeys = new int[12 * totalIterations]; // rotation key constants

        int maskConstant = 0x5A827999;
        int maskDelta = 0x6ED9EBA1;
        int rotationConstant = 19;
        int rotationDelta = 17;

        for (int i = 0; i < totalIterations; i++) {
            for (int j = 0; j < 12; j++) {
                int idx = i * 12 + j;
                TempMaskKeys[idx] = maskConstant;
                maskConstant = maskConstant + maskDelta;
                tempRotationKeys[idx] = rotationConstant % 32;
                rotationConstant = rotationConstant + rotationDelta;
            }
        }

        return new CASTKeySet(TempMaskKeys, tempRotationKeys);
    }

    @Override
    public CASTKeySet generateRoundKeys(CASTKeySet T, byte[] key, int roundCount, int dodecadCount) {
        int[] keyBlockWords = new int[12];

        // convert the key bytes into 32 bit words
        for (int wordIndex = 0; wordIndex < 12; wordIndex++) {
            int offset = wordIndex * 4;

            if (offset + 3 < key.length) {
                int byte0 = key[offset]     & 0xFF;
                int byte1 = key[offset + 1] & 0xFF;
                int byte2 = key[offset + 2] & 0xFF;
                int byte3 = key[offset + 3] & 0xFF;

                keyBlockWords[wordIndex] = (byte0 << 24) | (byte1 << 16) | (byte2 << 8) | byte3;
            } else {
                keyBlockWords[wordIndex] = 0;
            }
        }

        // retrieve arrays of temporary masking and rotation constants
        int[] Tm = T.getM();
        int[] Tr = T.getR();

        int[] Km = new int[roundCount * 6];
        int[] Kr = new int[roundCount * 6];


        // apply dodecad function multiple times
        for (int roundIndex = 0; roundIndex < roundCount; roundIndex++) {
            for (int dodecadIndex = 0; dodecadIndex < dodecadCount; dodecadIndex++) {
                int dodecadOfsset = (roundIndex * dodecadCount + dodecadIndex) * 12;
                dodecad(keyBlockWords, Tm, Tr, dodecadOfsset);
            }

            int base = roundIndex * 6;

            // get masking keys from transformed keyBlockWords
            Km[base] = keyBlockWords[11];
            Km[base + 1] = keyBlockWords[9];
            Km[base + 2] = keyBlockWords[7];
            Km[base + 3] = keyBlockWords[5];
            Km[base + 4] = keyBlockWords[3];
            Km[base + 5] = keyBlockWords[1];

            Kr[base] = keyBlockWords[0] & 31;
            Kr[base + 1] = keyBlockWords[2] & 31;
            Kr[base + 2] = keyBlockWords[4] & 31;
            Kr[base + 3] = keyBlockWords[6] & 31;
            Kr[base + 4] = keyBlockWords[8] & 31;
            Kr[base + 5] = keyBlockWords[10] & 31;
        }

        return new CASTKeySet(Km, Kr);
    }

    @Override
    public int f1 (int d, int Km, int Kr) {
        // mask input with km and rotate left by kr bits
        int rotatedInput = Integer.rotateLeft(Km + d, Kr);

        // split rotatedInput into four bytes
        int byte1 = (rotatedInput >>> 24) & 0xFF;
        int byte2 = (rotatedInput >>> 16) & 0xFF;
        int byte3 = (rotatedInput >>> 8) & 0xFF;
        int byte4 = rotatedInput & 0xFF;

        // combine outputs using F1 operation order
        return ((S1[byte1] ^ S2[byte2]) - S3[byte3]) + S4[byte4];
    }

    @Override
    public int f2 (int d, int Km, int Kr) {
        int rotatedInput = Integer.rotateLeft(Km ^ d, Kr);
        int byte1 = (rotatedInput >>> 24) & 0xFF;
        int byte2 = (rotatedInput >>> 16) & 0xFF;
        int byte3 = (rotatedInput >>> 8) & 0xFF;
        int byte4 = rotatedInput & 0xFF;

        // combine outputs using the F2 operation order
        return ((S1[byte1] - S2[byte2]) + S3[byte3]) ^ S4[byte4];
    }

    @Override
    public int f3 (int d, int Km, int Kr) {
        int rotatedInput = Integer.rotateLeft(Km - d, Kr);
        int byte1 = (rotatedInput >>> 24) & 0xFF;
        int byte2 = (rotatedInput >>> 16) & 0xFF;
        int byte3 = (rotatedInput >>> 8) & 0xFF;
        int byte4 = rotatedInput & 0xFF;

        // combine outputs using the F3 operation order
        return ((S1[byte1] + S2[byte2]) ^ S3[byte3]) - S4[byte4];
    }

    @Override
    public int f4 (int d, int Km, int Kr) {
        int rotatedInput = Integer.rotateLeft(Km - d, Kr);
        int byte1 = (rotatedInput >>> 24) & 0xFF;
        int byte2 = (rotatedInput >>> 16) & 0xFF;
        int byte3 = (rotatedInput >>> 8) & 0xFF;
        int byte4 = rotatedInput & 0xFF;

        // combine outputs using F4 operation order
        return ((S1[byte1] ^ S2[byte2]) + S3[byte3]) - S4[byte4];
    }

    @Override
    public int f5 (int d, int Km, int Kr) {
        int rotatedInput = Integer.rotateLeft(Km + d, Kr);
        int byte1 = (rotatedInput >>> 24) & 0xFF;
        int byte2 = (rotatedInput >>> 16) & 0xFF;
        int byte3 = (rotatedInput >>> 8) & 0xFF;
        int byte4 = rotatedInput & 0xFF;

        // combine outputs usign F5 operation order
        return ((S1[byte1] - S2[byte2]) ^ S3[byte3]) + S4[byte4];
    }

    @Override
    public int f6 (int d, int Km, int Kr) {
        int rotatedInput = Integer.rotateLeft(Km ^ d, Kr);
        int byte1 = (rotatedInput >>> 24) & 0xFF;
        int byte2 = (rotatedInput >>> 16) & 0xFF;
        int byte3 = (rotatedInput >>> 8) & 0xFF;
        int byte4 = rotatedInput & 0xFF;

        // combine output using F6 operation order
        return ((S1[byte1] + S2[byte2]) - S3[byte3]) ^ S4[byte4];
    }

    @Override
    public void dodecad(int[] block, int[] Tm, int[] Tr, int idx) {
        // apply 12 chained F-functions on the 384-bit key block
        block[10] ^= f1(block[11], Tm[idx], Tr[idx]);
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

        int t1 = f1(F, Km[idx], Kr[idx]);
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

        int t1 = f1(F, Km[idx], Kr[idx]);
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

            int b0 = data[index]     & 0xFF;
            int b1 = data[index + 1] & 0xFF;
            int b2 = data[index + 2] & 0xFF;
            int b3 = data[index + 3] & 0xFF;

            block[i] = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
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

            int b0 = data[index]     & 0xFF;
            int b1 = data[index + 1] & 0xFF;
            int b2 = data[index + 2] & 0xFF;
            int b3 = data[index + 3] & 0xFF;

            block[i] = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
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
