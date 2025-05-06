package uk.ac.nottingham.cryptography.Modes;

import org.junit.jupiter.api.*;
import uk.ac.nottingham.cryptography.CASTCipher;
import uk.ac.nottingham.cryptography.CipherMode;
import uk.ac.nottingham.cryptography.HexUtils;

import java.util.Arrays;
import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class CTRStreamTests {
    private final CASTCipher cipher = ServiceLoader.load(CASTCipher.class).findFirst().orElseThrow();
    private final CipherMode mode = ServiceLoader.load(CipherMode.class).findFirst().orElseThrow();

    private static final byte[] keyA;
    private static final byte[] keyB;

    private static final byte[] nonceA;

    private static final byte[] nonceB;

    private static final String expectedMultiBlockOutput =
            "5d57337f657881984dc008910a6e3276bff29371b844724346382709f39fa1ed9da9d32aa78ff40802205d22726f6236714c88734e8fa5efe59a17f8295b777c" +
                    "0131c8d783255240e3ea5c2a678d04acb3b5e8796fb5899c784535509cd5abade45eb84999af80dade2e239bb3a1ca0d33d11534ac2f4f03a8b4c0d6961124ae" +
                    "3a97d495aa92512197a2c61f5b39f629b37f16bce6f84a46cd80d36f8516a44334fb74efa4fb788aeb553f7c0e0f178cbed79fee7554e3140e2aa4a0095ac645" +
                    "fab7d2ed0c3500c070240c829328426cc3956ec4f9bd33eeec8341897d556a3ad5156ab67d5487b68c7e4a15bf433a2286b7085f61f17a65536f88f8fd7ba609" +
                    "3e7ac444656489f958f656c4f060542e21d2476ec9e88481f2b0a6c2e7d664611bad199f97db6982f7f059b9a2cc365b111035accbfa973348c337dcf42e43bb" +
                    "5abebacb355b301bdb9385e8564c4f3f9511bb003f9849936261e460bd73983a07c96341d1ef6ad806405cc78b6ce7aac39fd78e24ade380051251162fc01ab4" +
                    "9dd73ad71b104737ae34fb994e8382009e750824ec2fc66d688a335080ccb01e5adc938d196eff4b83c7048cffb2b2097ea263b025a4fcc05421ba434b149297" +
                    "702782f6848e9526405d5883b0a52973365277572667d6d38919eb499f8e20e82d4b10aa504cb61a75663835f5cd8b3b767d7661fb95671e33e9785a2783088e" +
                    "9fc71665355b433b7b5cf7a72418880b664a07a469cbf2628ea34dfb453d9ce7a3d45b826366e5fb33ca5a214ceb733457959e8e33ab9caea92ff4f82c8c9074" +
                    "4690944e3bf36ef87c8cc93c4a61be74f351fcba8599c203175f03ea7d8ac606e31cacf4862e98360af2067259d9b605402b2dbcbca0a0ddd6d0d183f271a48a" +
                    "885d25d591e6e42d63fde451c4e2fea2033ecd42449bce821b37da11923702fd1e46629f51a4e82705dff4ef7ea4ac72ceed86603374e64bb13c68d73661da69" +
                    "f7edae478c44194f6e2ab436f3dd32f32dc24100dd8817c93407515545453bda82b488d185f84c97c06b6ccf127f31ff379fef9722c7d1b2490f5eacbe6edb51" +
                    "66b100cb169fd4458fa8af3241b7b83b24e508e4f871fa6946c9aec36f7a383dbbd56f64e28512d982ec3bf668bbb56f7b4c82e741bebb82f007fc6f052f7fd9" +
                    "52e5871fc5e742362c4af808037293a7db68c165ff8767ca79d54584c24a133f98e8aa09acf3fb69ad1a0e94f5f4e1f98c56ee2f28838ab73d82d7e77c7853e6" +
                    "fa35732f4c343efb8200730c40d2c45099d090321a4f29ce46016964e97bca33e86c8af4f470157d79d8a8e06d955cfd7569eea00f3b2da3f2089cc07435191a" +
                    "c530dff34a2d16e93bc667216cd60393eb2c48f01cebad6f094cee2510cb9fb550a2704bb67534163a1c2842cbf15cb353f1f4a7664394c1e162f9089ae80c6c";
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
    void smallBlockEncryptTest() {
        byte[] block = new byte[3];
        for (int i = 0; i < block.length; i++) {
            block[i] = (byte)(0x1b & i);
        }

        mode.initialise(cipher, keyA, nonceA);
        mode.encrypt(block);

        byte[] expectedOutput = new byte[] { 93, 87, 51 };

        assertArrayEquals(expectedOutput, block);
    }


    @Test
    @Order(1)
    void smallBlockDecryptTest() {
        byte[] block = new byte[15];
        for (int i = 0; i < block.length; i++) {
            block[i] = (byte)(0x1b & i);
        }

        mode.initialise(cipher, keyA, nonceA);
        mode.decrypt(block);

        byte[] expectedOutput = new byte[] { 93, 87, 51, 127, 101, 120, -127, -104, 77, -64, 8, -111, 10, 110, 50 };

        assertArrayEquals(expectedOutput, block);
    }

    @Test
    @Order(2)
    void largeBlockEncryptTest() {
        byte[] block = new byte[32];
        for (int i = 0; i < block.length; i++) {
            block[i] = (byte)(0x1b & i);
        }

        mode.initialise(cipher, keyA, nonceA);
        mode.encrypt(block);

        byte[] expectedOutput = new byte[] { 93, 87, 51, 127, 101, 120, -127, -104, 77, -64, 8,
                -111, 10, 110, 50, 118, -65, -14, -109, 113, -72, 68, 114, 67, 70, 56, 39, 9, -13,
                -97, -95, -19 };

        assertArrayEquals(expectedOutput, block);
    }

    @Test
    @Order(2)
    void largeBlockDecryptTest() {
        byte[] block = new byte[41];
        for (int i = 0; i < block.length; i++) {
            block[i] = (byte)(0x1b & i);
        }

        mode.initialise(cipher, keyB, nonceA);
        mode.decrypt(block);

        byte[] expectedOutput = new byte[] { -97, -40, -12, 101, -9, -102, 58, 53, 42, -26,
                30, -102, -12, 65, 117, 117, 98, -42, 19, 74, -13, 26, 4, -79, -52, -79, -53,
                116, 48, -44, 11, -3, -49, 117, 64, -47, -105, 122, -51, -118, 82 };

        assertArrayEquals(expectedOutput, block);
    }

    @Test
    @Order(3)
    void doubleBlockEncryptTest() {
        byte[] block = new byte[48];
        for (int i = 0; i < block.length; i++) {
            block[i] = (byte)(0x1b & i);
        }

        mode.initialise(cipher, keyA, nonceB);
        mode.encrypt(block);

        byte[] expectedOutput = new byte[] { 37, 20, 117, -1, 83, -101, 20, 43, -122, 107, -61,
                84, 101, 8, 86, -67, -44, -20, 17, -100, -2, 114, 23, -93, 71, -100, 0, 25, 58,
                77, -98, -15, 35, 120, -47, 110, 125, -114, 55, 53, 102, 73, -125, 65, 13, -115, 78, -127 };

        assertArrayEquals(expectedOutput, block);
    }

    @Test
    @Order(4)
    void tripleBlockDecryptTest() {
        byte[] block = new byte[24*3];
        for (int i = 0; i < block.length; i++) {
            block[i] = (byte)(0x1b & i);
        }

        mode.initialise(cipher, keyA, nonceB);
        mode.decrypt(block);

        byte[] expectedOutput = new byte[] { 37, 20, 117, -1, 83, -101, 20, 43, -122, 107, -61, 84, 101, 8, 86, -67, -44, -20, 17, -100, -2, 114, 23, -93, 71, -100, 0, 25, 58, 77, -98, -15, 35, 120, -47, 110, 125, -114, 55, 53, 102, 73, -125, 65, 13, -115, 78, -127, 61, 16, 28, -90, 125, 23, 122, 117, -38, 10, 14, -1, -92, -38, 113, -65, 69, 65, -100, -3, -76, -101, 58, 110 };

        assertArrayEquals(expectedOutput, block);
    }

    @Test
    @Order(5)
    void multiPartialBlockEncryptTest1() {

        int[] sizes = new int[] { 10, 24, 14 };
        int[] starts = new int[sizes.length];
        for (int c = 1; c < sizes.length; c++)
        {
            starts[c] = starts[c-1] + sizes[c-1];
        }

        int sum = sizes[sizes.length - 1] + starts[starts.length -1];

        byte[] block = new byte[sum];
        for (int i = 0; i < block.length; i++) {
            block[i] = (byte)(0x1b & i);
        }

        mode.initialise(cipher, keyA, nonceA);

        for (int b = 0; b < sizes.length; b++) {
            byte[] currentBlock = Arrays.copyOfRange(block, starts[b], starts[b] + sizes[b]);
            byte[] expectedBlock = HexUtils.hexToBytes(expectedMultiBlockOutput.substring(starts[b] * 2, (starts[b] + sizes[b]) * 2));
            mode.encrypt(currentBlock);
            assertArrayEquals(expectedBlock, currentBlock);
        }
    }

    @Test
    @Order(6)
    void multiPartialBlockDecryptTest1() {

        int[] sizes = new int[] { 10, 10, 30, 12, 19 };
        int[] starts = new int[sizes.length];
        for (int c = 1; c < sizes.length; c++)
        {
            starts[c] = starts[c-1] + sizes[c-1];
        }

        int sum = sizes[sizes.length - 1] + starts[starts.length -1];

        byte[] block = new byte[sum];
        for (int i = 0; i < block.length; i++) {
            block[i] = (byte)(0x1b & i);
        }

        mode.initialise(cipher, keyA, nonceA);

        for (int b = 0; b < sizes.length; b++) {
            byte[] currentBlock = Arrays.copyOfRange(block, starts[b], starts[b] + sizes[b]);
            byte[] expectedBlock = HexUtils.hexToBytes(expectedMultiBlockOutput.substring(starts[b] * 2, (starts[b] + sizes[b]) * 2));
            mode.decrypt(currentBlock);
            assertArrayEquals(expectedBlock, currentBlock);
        }
    }

    @Test
    @Order(7)
    void multiPartialBlockEncryptTest2() {

        int[] sizes = new int[] { 24, 24, 24, 12, 24, 24, 24, 48, 15, 12, 7, 5 };
        int[] starts = new int[sizes.length];
        for (int c = 1; c < sizes.length; c++)
        {
            starts[c] = starts[c-1] + sizes[c-1];
        }

        int sum = sizes[sizes.length - 1] + starts[starts.length -1];

        byte[] block = new byte[sum];
        for (int i = 0; i < block.length; i++) {
            block[i] = (byte)(0x1b & i);
        }

        mode.initialise(cipher, keyA, nonceA);

        for (int b = 0; b < sizes.length; b++) {
            byte[] currentBlock = Arrays.copyOfRange(block, starts[b], starts[b] + sizes[b]);
            byte[] expectedBlock = HexUtils.hexToBytes(expectedMultiBlockOutput.substring(starts[b] * 2, (starts[b] + sizes[b]) * 2));
            mode.encrypt(currentBlock);
            assertArrayEquals(expectedBlock, currentBlock);
        }
    }

    @Test
    @Order(7)
    void multiPartialBlockDecryptTest2() {

        int[] sizes = new int[] { 1, 2, 4, 8, 16, 32, 64, 24, 24, 24, 24, 24 };
        int[] starts = new int[sizes.length];
        for (int c = 1; c < sizes.length; c++)
        {
            starts[c] = starts[c-1] + sizes[c-1];
        }

        int sum = sizes[sizes.length - 1] + starts[starts.length -1];

        byte[] block = new byte[sum];
        for (int i = 0; i < block.length; i++) {
            block[i] = (byte)(0x1b & i);
        }

        mode.initialise(cipher, keyA, nonceA);

        for (int b = 0; b < sizes.length; b++) {
            byte[] currentBlock = Arrays.copyOfRange(block, starts[b], starts[b] + sizes[b]);
            byte[] expectedBlock = HexUtils.hexToBytes(expectedMultiBlockOutput.substring(starts[b] * 2, (starts[b] + sizes[b]) * 2));
            mode.decrypt(currentBlock);
            assertArrayEquals(expectedBlock, currentBlock);
        }
    }

}

