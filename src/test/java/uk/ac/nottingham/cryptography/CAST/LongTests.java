package uk.ac.nottingham.cryptography.CAST;

import org.junit.jupiter.api.*;
import uk.ac.nottingham.cryptography.CASTCipher;

import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class LongTests {
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

    @BeforeAll
    void burnIn() {
        byte[] block = new byte[24];
        cipher.initialise(new byte[48]);
        for (int i = 0; i < 100000; i++) {
            cipher.encrypt(block);
        }
    }

    @Test
    @Order(0)
    void long100kbTest() {
        byte[] block = new byte[24];
        for (int i = 0; i < 24; i++) {
            block[i] = (byte)(0x1b & i);
        }

        cipher.initialise(keyA);

        for (int i = 0; i < 4167; i++) {
            cipher.encrypt(block);
        }

        byte[] expectedOutput = new byte[] {
                -127, 0, 29, -21, -86, -123, 116, 15, 91, 79, 42, -36, 116, -26, -22, -50, -94, -10, -29, -59, -35, 56, -24, 51
        };

        assertArrayEquals(expectedOutput, block);
    }

    @Test
    @Order(1)
    void long1MbTest() {
        byte[] block = new byte[24];
        for (int i = 0; i < 24; i++) {
            block[i] = (byte)(0x1b & i);
        }

        cipher.initialise(keyA);

        for (int i = 0; i < 41667; i++) {
            cipher.encrypt(block);
        }

        byte[] expectedOutput = new byte[] {
                -98, -25, 13, -77, -109, -106, -39, -126, 1, 45, 82, -88, 15, 103, 73, 73, -78, -111, 9, -83, 94, 44, -56, -101
        };

        assertArrayEquals(expectedOutput, block);
    }

    @Test
    @Order(2)
    void long10MbTest() {
        byte[] block = new byte[24];
        for (int i = 0; i < 24; i++) {
            block[i] = (byte)(0x1b & i);
        }

        cipher.initialise(keyA);

        for (int i = 0; i < 416667; i++) {
            cipher.encrypt(block);
        }

        byte[] expectedOutput = new byte[] {
                1, 63, 8, -12, 117, -25, -26, -65, 26, 42, -110, -78, 43, -111, 39, 75, -63, -115, -3, 48, -74, -55, -44, -36
        };

        assertArrayEquals(expectedOutput, block);
    }

    @Test
    @Order(3)
    void long100MbTest() {
        byte[] block = new byte[24];
        for (int i = 0; i < 24; i++) {
            block[i] = (byte)(0x1b & i);
        }

        cipher.initialise(keyA);

        for (int i = 0; i < 4166667; i++) {
            cipher.encrypt(block);
        }

        byte[] expectedOutput = new byte[] {
                -32, 73, -25, 17, -104, 103, -66, 91, -67, -22, -72, 82, 48, -62, -115, -121, 88, 42, -117, 122, -1, 99, -58, -88
        };

        assertArrayEquals(expectedOutput, block);
    }
}

