package uk.ac.nottingham.cryptography.Modes;

import org.junit.jupiter.api.*;
import uk.ac.nottingham.cryptography.CASTCipher;
import uk.ac.nottingham.cryptography.CipherMode;
import uk.ac.nottingham.cryptography.HexUtils;

import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class CTREncryptTests {
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
    void singleBlockEncryptTest() {
        byte[] block = new byte[24];
        for (int i = 0; i < 24; i++) {
            block[i] = (byte)(0x1b & i);
        }

        mode.initialise(cipher, keyA, nonceA);
        mode.encrypt(block);

        byte[] expectedOutput = new byte[] {
                (byte)0x5D,(byte)0x57,(byte)0x33,(byte)0x7F,(byte)0x65,(byte)0x78,(byte)0x81,(byte)0x98,
                (byte)0x4D,(byte)0xC0,(byte)0x08,(byte)0x91,(byte)0x0A,(byte)0x6E,(byte)0x32,(byte)0x76,
                (byte)0xBF,(byte)0xF2,(byte)0x93,(byte)0x71,(byte)0xB8,(byte)0x44,(byte)0x72,(byte)0x43
        };

        assertArrayEquals(expectedOutput, block);
    }

    @Test
    @Order(1)
    void doubleBlockEncryptTest() {
        byte[][] block = new byte[2][];
        for (int j = 0; j < block.length; j++) {
            block[j] = new byte[24];
            for (int i = 0; i < 24; i++) {
                block[j][i] = (byte) (0x8b & (i + j));
            }
        }

        mode.initialise(cipher, keyA, nonceB);

        String[] outputs = new String[block.length];

        for (int j = 0; j < block.length; j++) {
            mode.encrypt(block[j]);
            outputs[j] = HexUtils.bytesToHex(block[j]);
        }

        String[] expectedOutput = new String[] {
                "251475ff539b142b866bc354650856bdc4fc018cee6207b3",
                "5e871902235687e22a73d86574853e366f428a4a04864782"
        };

        for (int j = 0; j < block.length; j++) {
            assertArrayEquals(HexUtils.hexToBytes(expectedOutput[j]), block[j]);
        }
    }

    @Test
    @Order(2)
    void multiBlockEncryptTest() {
        byte[][] block = new byte[10][];
        for (int j = 0; j < block.length; j++) {
            block[j] = new byte[24];
            for (int i = 0; i < 24; i++) {
                block[j][i] = (byte) (0x8b & (i + j));
            }
        }

        mode.initialise(cipher, keyB, nonceA);

        String[] outputs = new String[block.length];

        for (int j = 0; j < block.length; j++) {
            mode.encrypt(block[j]);
            outputs[j] = HexUtils.bytesToHex(block[j]);
        }

        String[] expectedOutput = new String[] {
                "9fd8f465f79a3a352ae61e9af441757572c6035ae30a14a1",
                "d5aad26f29cf12eec67e49da9e71c4895b0b2ff5adcefa65",
                "80442c366d99276af506b57b785e1f38af72ba4d17094ed2",
                "c4deb6f5107822abd152eeb7940fcc232ce3a440a4fddbdd",
                "e38742a5cd932d682f235a32aea2fc5aa9310597b38c3562",
                "1f83e8681b205d551975c98d662045401aff7cace29fe978",
                "2f5680f7ec4d69dbea0641a57cd5f69b8f20d30713394ea1",
                "ba145d4dbdc59125409340e448509f0c1ee7bd5926e443be",
                "95e500b8855dec5578ad9380bef568ceaa784ed28fc59d60",
                "4ec9229558420a7076f65f02bca7a36d3b7eaae180a145b7"
        };

        for (int j = 0; j < block.length; j++) {
            assertArrayEquals(HexUtils.hexToBytes(expectedOutput[j]), block[j]);
        }
    }


    @Test
    @Order(3)
    void inlineBlockEncryptTest() {
        byte[] block = new byte[24];
        for (int i = 0; i < 24; i++) {
            block[i] = (byte) (0xAb & (i));
        }

        mode.initialise(cipher, keyB, nonceB);

        String output;

        for (int i = 0; i < 100; i++) {
            mode.encrypt(block);
        }

        String expectedOutput = "7fb0cd9b0f6ff8479516e1395166cc2e9ad0fd0e25fab746";

        assertArrayEquals(HexUtils.hexToBytes(expectedOutput), block);
    }


}

