package uk.ac.nottingham.cryptography.CAST;

import org.junit.jupiter.api.*;
import uk.ac.nottingham.cryptography.CASTCipher;
import uk.ac.nottingham.cryptography.HexUtils;

import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class DecryptTests {
    private final CASTCipher cipher = ServiceLoader.load(CASTCipher.class).findFirst().orElseThrow();

    private static final byte[] keyA;
    private static final byte[] keyB;

    static {
        keyA = new byte[48];
        keyB = new byte[48];

        for (int i = 0; i < 48; i++) {
            keyA[i] = (byte) (i + 3);
            keyB[i] = (byte) (i * 11);
        }
    }

    @Test
    @Order(0)
    void singleDecryptTest1() {
        byte[] block = new byte[24];
        for (int i = 0; i < 24; i++) {
            block[i] = (byte)(0x1b & i);
        }

        cipher.initialise(keyA);
        cipher.decrypt(block);

        String expectedOutput = "5332020dd65950399573b812b20de45f691b66bd9c841846";

        assertArrayEquals(HexUtils.hexToBytes(expectedOutput), block);
    }

    @Test
    @Order(1)
    void singleDecryptTest2() {
        byte[] block = new byte[24];
        for (int i = 0; i < 24; i++) {
            block[i] = (byte)i;
        }

        cipher.initialise(keyB);
        cipher.decrypt(block);

        String expectedOutput = "c0bc2d498a76a4a55aa33f6d885e1cc345df2f67ca3c9024";

        assertArrayEquals(HexUtils.hexToBytes(expectedOutput), block);
    }

    @Test
    @Order(2)
    void multiDecryptTest() {
        byte[] block = new byte[24];
        for (int i = 0; i < 24; i++) {
            block[i] = (byte)(0xFA ^ i);
        }

        cipher.initialise(keyB);

        for (int i = 0; i < 5; i++) {
            cipher.decrypt(block);
        }

        String expectedOutput = "88d4190bd860fe8cc9df3d0a4f5135ea024a66344e60e60b";

        assertArrayEquals(HexUtils.hexToBytes(expectedOutput), block);
    }
}

