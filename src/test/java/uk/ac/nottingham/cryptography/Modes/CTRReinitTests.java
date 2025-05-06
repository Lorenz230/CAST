package uk.ac.nottingham.cryptography.Modes;

import org.junit.jupiter.api.*;
import uk.ac.nottingham.cryptography.CASTCipher;
import uk.ac.nottingham.cryptography.CipherMode;
import uk.ac.nottingham.cryptography.HexUtils;

import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class CTRReinitTests {
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
    void immediateReinitTest() {
        byte[] block = new byte[24];
        for (int i = 0; i < 24; i++) {
            block[i] = (byte) (0xCB & (i));
        }

        String expectedOutput = "f8419d37591ea2e5f99d2864d54afb101b800c91e69ab145";

        mode.initialise(cipher, keyA, nonceA);
        mode.initialise(cipher, keyA, nonceB);
        mode.initialise(cipher, keyB, nonceA);
        mode.initialise(cipher, keyB, nonceB);
        mode.encrypt(block);
        assertArrayEquals(HexUtils.hexToBytes(expectedOutput), block);
    }

    @Test
    @Order(0)
    void singleReinitTest() {
        byte[] source = new byte[24];
        byte[] block = new byte[24];
        for (int i = 0; i < 24; i++) {
            source[i] = (byte) (0xCB & (i));
        }

        String[] expectedOutput = new String[] {
                "5d57337f657881984dc008910a6e3276afe28361a8546253",
                "f8419d37591ea2e5f99d2864d54afb101b800c91e69ab145"
        };

        System.arraycopy(source,0,block,0,24);
        mode.initialise(cipher, keyA, nonceA);
        mode.encrypt(block);
        assertArrayEquals(HexUtils.hexToBytes(expectedOutput[0]), block);

        System.arraycopy(source,0,block,0,24);
        mode.initialise(cipher, keyB, nonceB);
        mode.encrypt(block);
        assertArrayEquals(HexUtils.hexToBytes(expectedOutput[1]), block);
    }

    @Test
    @Order(0)
    void multiReinitTest() {
        byte[] source = new byte[24];
        byte[] block = new byte[24];
        for (int i = 0; i < 24; i++) {
            source[i] = (byte) (0xCB & (i));
        }

        String[] expectedOutput = new String[] {
                "5d57337f657881984dc008910a6e3276afe28361a8546253",
                "251475ff539b142b866bc354650856bdc4fc018cee6207b3",
                "9fd8f465f79a3a352ae61e9af441757572c6035ae30a14a1",
                "f8419d37591ea2e5f99d2864d54afb101b800c91e69ab145"
        };

        System.arraycopy(source,0,block,0,24);
        mode.initialise(cipher, keyA, nonceA);
        mode.encrypt(block);
        assertArrayEquals(HexUtils.hexToBytes(expectedOutput[0]), block);

        System.arraycopy(source,0,block,0,24);
        mode.initialise(cipher, keyA, nonceB);
        mode.encrypt(block);
        assertArrayEquals(HexUtils.hexToBytes(expectedOutput[1]), block);

        System.arraycopy(source,0,block,0,24);
        mode.initialise(cipher, keyB, nonceA);
        mode.encrypt(block);
        assertArrayEquals(HexUtils.hexToBytes(expectedOutput[2]), block);

        System.arraycopy(source,0,block,0,24);
        mode.initialise(cipher, keyB, nonceB);
        mode.encrypt(block);
        assertArrayEquals(HexUtils.hexToBytes(expectedOutput[3]), block);
    }

    @Test
    @Order(0)
    void fullReinitTest() {
        byte[] source = new byte[24];
        byte[] block = new byte[24];
        for (int i = 0; i < 24; i++) {
            source[i] = (byte) (0xCB & (i));
        }

        String[] expectedOutput = new String[] {
                "9324180f31d50869b498fb82ec03233c0df60e7ad18bfdaa",
                "dd16381911dc9954bf1edc21a39938516072e9eae3bb8056"
        };

        System.arraycopy(source,0,block,0,24);
        mode.initialise(cipher, keyA, nonceA);
        for (int i = 0; i < 10; i++) {
            mode.encrypt(block);
        }
        assertArrayEquals(HexUtils.hexToBytes(expectedOutput[0]), block);

        System.arraycopy(source,0,block,0,24);
        mode.initialise(cipher, keyA, nonceB);
        for (int i = 0; i < 10; i++) {
            mode.encrypt(block);
        }
        assertArrayEquals(HexUtils.hexToBytes(expectedOutput[1]), block);
    }
}

