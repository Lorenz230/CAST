package uk.ac.nottingham.cryptography.Modes;

import org.junit.jupiter.api.*;
import uk.ac.nottingham.cryptography.CASTCipher;
import uk.ac.nottingham.cryptography.CipherMode;
import uk.ac.nottingham.cryptography.HexUtils;

import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class CTRSeekTests {
    private final CASTCipher cipher = ServiceLoader.load(CASTCipher.class).findFirst().orElseThrow();
    private final CipherMode mode = ServiceLoader.load(CipherMode.class).findFirst().orElseThrow();

    private static final byte[] keyA;
    private static final byte[] keyB;

    private static final byte[] nonceA;

    private static final byte[] nonceB;

    static {
        keyA = new byte[48];
        keyB = new byte[48];

        for (int i = 0; i < 48; i++) {
            keyA[i] = (byte) (i + 3);
            keyB[i] = (byte) (i * 11);
        }

        nonceA = new byte[16];
        nonceB = new byte[16];

        for (int i = 0; i < 16; i++) {
            nonceA[i] = (byte) (i * 3 + 19);
            nonceB[i] = (byte) (i * 17);
        }
    }

    @Test
    @Order(0)
    void singleSeekTest1() {
        byte[] source = new byte[24];
        byte[] block = new byte[24];
        for (int i = 0; i < 24; i++) {
            source[i] = (byte) (0xCB & (i));
        }

        String[] expectedOutput = new String[] {
                "5d57337f657881984dc008910a6e3276afe28361a8546253",
                "ebe254226f850ca4abadf06177ad9184605d2d4884cdb3b5"
        };

        System.arraycopy(source,0,block,0,24);
        mode.initialise(cipher, keyA, nonceA);
        mode.encrypt(block);
        assertArrayEquals(HexUtils.hexToBytes(expectedOutput[0]), block);

        System.arraycopy(source,0,block,0,24);
        mode.seek(new byte[] { 3 });
        mode.encrypt(block);
        assertArrayEquals(HexUtils.hexToBytes(expectedOutput[1]), block);
    }

    @Test
    @Order(1)
    void singleSeekTest2() {
        byte[] source = new byte[24];
        byte[] block = new byte[24];
        for (int i = 0; i < 24; i++) {
            source[i] = (byte) (0xCB & (i));
        }

        String[] expectedOutput = new String[] {
                "251475ff539b142b866bc354650856bdc4fc018cee6207b3",
                "fca5f2e93b9d8d43a6df17357b5250bc0f4131617955ecee"
        };

        System.arraycopy(source,0,block,0,24);
        mode.initialise(cipher, keyA, nonceB);
        mode.encrypt(block);
        assertArrayEquals(HexUtils.hexToBytes(expectedOutput[0]), block);

        System.arraycopy(source,0,block,0,24);
        mode.seek(new byte[] { 0x01, (byte)0xFF});
        mode.encrypt(block);
        assertArrayEquals(HexUtils.hexToBytes(expectedOutput[1]), block);
    }

    @Test
    @Order(2)
    void multiSeekTest() {
        byte[] source = new byte[24];
        byte[] block = new byte[24];
        for (int i = 0; i < 24; i++) {
            source[i] = (byte) (0xCB & (i));
        }

        String[] expectedOutput = new String[] {
                "5e203f11eb87b9f595a1db22af87fc000a28552a7a676a3e",
                "e7a75ec6e3499999a68c69c03521ac35f2aff6f7ff92508d",
                "518802beedc71755dca4ec60246893f7494ff6198e3f995e",
                "cd89eff99e8ed40950063744e75041bbb4d44a99d03c233c"
        };

        mode.initialise(cipher, keyA, nonceA);

        System.arraycopy(source,0,block,0,24);
        mode.seek(new byte[] { 1 });
        mode.encrypt(block);
        assertArrayEquals(HexUtils.hexToBytes(expectedOutput[0]), block);

        System.arraycopy(source,0,block,0,24);
        mode.seek(new byte[] { 14, 7, 1 });
        mode.encrypt(block);
        assertArrayEquals(HexUtils.hexToBytes(expectedOutput[1]), block);

        System.arraycopy(source,0,block,0,24);
        mode.seek(new byte[] { 6, 121, 7, 8, 1 });
        mode.encrypt(block);
        assertArrayEquals(HexUtils.hexToBytes(expectedOutput[2]), block);

        System.arraycopy(source,0,block,0,24);
        mode.seek(new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 });
        mode.encrypt(block);
        assertArrayEquals(HexUtils.hexToBytes(expectedOutput[3]), block);
    }
}

