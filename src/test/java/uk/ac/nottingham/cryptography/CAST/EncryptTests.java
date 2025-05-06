package uk.ac.nottingham.cryptography.CAST;

import org.junit.jupiter.api.*;
import uk.ac.nottingham.cryptography.CASTCipher;

import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class EncryptTests {
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
    void singleEncryptTest1() {
        byte[] block = new byte[24];
        for (int i = 0; i < 24; i++) {
            block[i] = (byte)(0x1b & i);
        }

        cipher.initialise(keyA);
        cipher.encrypt(block);
        byte[] expectedOutput = new byte[] {
                (byte)0x2A,(byte)0xFA,(byte)0x97,(byte)0x6B,(byte)0xE7,(byte)0xCB,(byte)0x76,
                (byte)0xA9,(byte)0x4B,(byte)0xE2,(byte)0xB4,(byte)0x78,(byte)0x33,(byte)0x5B,
                (byte)0x57,(byte)0xFB,(byte)0x74,(byte)0x34,(byte)0xC2,(byte)0x8B,(byte)0x88,
                (byte)0x55,(byte)0xB7,(byte)0xC3
        };

        assertArrayEquals(expectedOutput, block);
    }

    @Test
    @Order(1)
    void singleEncryptTest2() {
        byte[] block = new byte[24];
        for (int i = 0; i < 24; i++) {
            block[i] = (byte)i;
        }

        cipher.initialise(keyB);
        cipher.encrypt(block);
        byte[] expectedOutput = new byte[] {
                (byte)0xD7,(byte)0xD1,(byte)0x3B,(byte)0xA0,(byte)0x43,(byte)0xCA,(byte)0x79,
                (byte)0x53,(byte)0x13,(byte)0x7B,(byte)0xC6,(byte)0xDB,(byte)0x9C,(byte)0xC2,
                (byte)0x01,(byte)0xF2,(byte)0xE4,(byte)0x38,(byte)0x6C,(byte)0x55,(byte)0x66,
                (byte)0x24,(byte)0x0A,(byte)0xE5,
        };

        assertArrayEquals(expectedOutput, block);
    }

    @Test
    @Order(2)
    void multiEncryptTest() {
        byte[] block = new byte[24];
        for (int i = 0; i < 24; i++) {
            block[i] = (byte)(0xFA ^ i);
        }

        cipher.initialise(keyB);

        for (int i = 0; i < 5; i++) {
            cipher.encrypt(block);
        }

        byte[] expectedOutput = new byte[] {
                (byte)0xD2,(byte)0x2B,(byte)0x3F,(byte)0x25,(byte)0xA9,(byte)0x2C,(byte)0x55,
                (byte)0x5D,(byte)0xEB,(byte)0x3D,(byte)0xD2,(byte)0x85,(byte)0xDB,(byte)0xD2,
                (byte)0x89,(byte)0x4E,(byte)0xD6,(byte)0x64,(byte)0x6B,(byte)0x2E,(byte)0x0A,
                (byte)0xE6,(byte)0x41,(byte)0xD6
        };

        assertArrayEquals(expectedOutput, block);
    }

}

