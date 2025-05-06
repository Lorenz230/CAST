package uk.ac.nottingham.cryptography.CAST;

import org.junit.jupiter.api.*;
import uk.ac.nottingham.cryptography.CASTCipher;

import java.util.Arrays;
import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class EncryptDecryptTests {
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
    void singleInvertTest() {
        byte[] block = new byte[24];
        for (int i = 0; i < 24; i++) {
            block[i] = (byte)(0x1b & i);
        }

        byte[] expectedOutput = new byte[24];
        System.arraycopy(block, 0, expectedOutput, 0, 24);

        cipher.initialise(keyA);

        cipher.encrypt(block);

        assertFalse(Arrays.equals(expectedOutput, block));

        cipher.decrypt(block);

        assertArrayEquals(expectedOutput, block);
    }

    @Test
    @Order(1)
    void doubleInvertTest() {
        byte[] block = new byte[24];
        for (int i = 0; i < 24; i++) {
            block[i] = (byte)(0xFA ^ i);
        }

        byte[] expectedOutput = new byte[24];
        System.arraycopy(block, 0, expectedOutput, 0, 24);

        cipher.initialise(keyA);

        cipher.encrypt(block);
        cipher.encrypt(block);

        assertFalse(Arrays.equals(expectedOutput, block));

        cipher.decrypt(block);
        cipher.decrypt(block);

        assertArrayEquals(expectedOutput, block);
    }

    @Test
    @Order(2)
    void multiInvertTest() {
        byte[] block = new byte[24];
        for (int i = 0; i < 24; i++) {
            block[i] = (byte)(0xAC ^ i);
        }

        byte[] expectedOutput = new byte[24];
        System.arraycopy(block, 0, expectedOutput, 0, 24);

        cipher.initialise(keyB);

        for (int i = 0; i < 10; i++) {
            cipher.encrypt(block);
        }

        assertFalse(Arrays.equals(expectedOutput, block));

        for (int i = 0; i < 10; i++) {
            cipher.decrypt(block);
        }

        assertArrayEquals(expectedOutput, block);
    }

}

