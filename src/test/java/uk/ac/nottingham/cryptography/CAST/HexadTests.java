package uk.ac.nottingham.cryptography.CAST;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import uk.ac.nottingham.cryptography.CASTCipher;

import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class HexadTests {
    private final CASTCipher cipher = ServiceLoader.load(CASTCipher.class).findFirst().orElseThrow();

    private static final int[] Km = new int[] {
        0xA059042A,0x6043951A,0xAB5EBDD9,0x1F08F1E3,0xF338524B,0x122AB0AB,0x748FF608,
                0xED2F44D2,0xD992257B,0x45F35F30,0x03095AB4,0xDFA1237A,0xC558DB69,0x0B1ACFEA,
                0xCC47E33D,0xAE75BB1F,0xFFDEAE44,0x078CCC41,0x68AB27C6,0x547FD168,0xFADB4143,
                0x9A67583E,0xA9F735B7,0x0CDAECE2,0x02E63D1F,0x8A61E30F,0x5B8C743B,0x08C50D7D,
                0x86F8FC94,0x1ABA0786,0x470798C0,0x44C6F50D,0x48C948E4,0x1BC7DC9B,0xFC3BAB79,
                0x026CFFCA,0xB20F2653,0x4E9BD5E6,0x07B81BDF,0x12128CD0,0x3B07B0AC,0x3D483425,
                0xB74CE52C,0x4681F6A0,0x46C707BA,0x7BB805BC,0x483EC2DE,0x226B1B9D,0x1A2B4BD0,
                0x1F35B730,0x5F1D753A,0x0DF27690,0x9A82AA42,0x1D0333AB,0xF56E15C7,0x28DAC725,
                0x513679E9,0x2AA5957C,0x7D9B7BCF,0x1C0B4A6C,0xCA0D67A4,0xACC66694,0xD9DEB0E1,
                0x23748358,0xC1D6B2D1,0x3BCC7109,0xE7117552,0xE7959343,0xC39079D8,0x478E1F96,
                0xC89CD4B7,0xA4242268
    };

    private static final int[] Kr = new int[] {
            5,0,5,16,26,24,14,8,14,10,4,23,11,6,31,5,20,11,
            9,13,29,17,0,0,13,0,24,1,3,22,22,8,14,6,21,31,20,
            19,5,7,12,25,7,20,4,5,18,13,27,24,18,13,8,7,3,5,
            17,30,26,23,21,24,29,28,3,9,6,0,0,21,3,1
    };

    @Test
    void singleHexadTest1() {

        int[] block = new int[] { 0, 1, 2, 3, 4, 5 };

        int[] expectedOutput = new int[] {
                0x9EA6C539,
                0xB62E7C65,
                0x3505D5B9,
                0x339FF921,
                0x8AD3FF72,
                0x63396D7E
        };

        cipher.hexad(block, Km, Kr, 0);
        assertArrayEquals(expectedOutput, block);
    }

    @Test
    void singleHexadTest2() {

        int[] block = new int[] { 0, 1, 2, 3, 4, 5 };

        int[] expectedOutput = new int[] {
                0x286F9B2A,
                0xC30626B7,
                0x8C94E6B6,
                0xCEA94373,
                0x437CDAEB,
                0xB8FC970E
        };

        cipher.hexad(block, Km, Kr, 6);
        assertArrayEquals(expectedOutput, block);
    }

    @Test
    void singleHexadInvTest1() {

        int[] block = new int[] { 0, 1, 2, 3, 4, 5 };

        int[] expectedOutput = new int[] {
                0xDC32CD51,
                0x506114E2,
                0x646182AA,
                0x46DDCDF2,
                0x9940D3B9,
                0xF7EC252F
        };

        cipher.hexadInv(block, Km, Kr, 0);
        assertArrayEquals(expectedOutput, block);
    }

    @Test
    void singleHexadInvTest2() {

        int[] block = new int[] { 0, 1, 2, 3, 4, 5 };

        int[] expectedOutput = new int[] {
                0x79059EF5,
                0xE13139E2,
                0x33F73515,
                0xF88E1213,
                0xE72CDC2B,
                0x4C6ADE21
        };

        cipher.hexadInv(block, Km, Kr, 6);
        assertArrayEquals(expectedOutput, block);
    }

    @Test
    void doubleHexadTest() {

        int[] block = new int[] { 0, 1, 2, 3, 4, 5 };

        int[] expectedOutput = new int[]{
                0x6FDF4660,
                0x3BA6C558,
                0xBE2EDED9,
                0x34061C55,
                0x5475C602,
                0x436A6073
        };

        cipher.hexad(block, Km, Kr, 0);
        cipher.hexad(block, Km, Kr, 6);
        assertArrayEquals(expectedOutput, block);
    }

    @Test
    void doubleHexadInvTest() {

        int[] block = new int[] { 0, 1, 2, 3, 4, 5 };

        int[] expectedOutput = new int[]{
                0xBAF2A7ED,
                0x6CF15B18,
                0xA4AD2505,
                0xBEDE4DBF,
                0xF3ED8F34,
                0x6979DA2B
        };

        cipher.hexadInv(block, Km, Kr, 0);
        cipher.hexadInv(block, Km, Kr, 6);
        assertArrayEquals(expectedOutput, block);
    }

    @Test
    void loopedHexadTest() {

        int[] block = new int[] { 0, 1, 2, 3, 4, 5 };

        int[] expectedOutput = new int[]{
                0x67E3AD61,
                0xC9FB8AE6,
                0x68BB8274,
                0x238131A0,
                0x52A3074F,
                0x113A7080
        };

        for (int i = 0; i < 36; i+=6) {
            cipher.hexad(block, Km, Kr, i);
        }
        assertArrayEquals(expectedOutput, block);
    }

    @Test
    void loopedHexadInvTest() {

        int[] block = new int[] { 0, 1, 2, 3, 4, 5 };

        int[] expectedOutput = new int[]{
                0x0B15D512,
                0xF8759820,
                0x3D27924B,
                0xEC45CCFC,
                0x28A690AC,
                0x1CB5A988
        };

        for (int i = 0; i < 36; i+=6) {
            cipher.hexadInv(block, Km, Kr, i);
        }
        assertArrayEquals(expectedOutput, block);
    }

    @Test
    void invertabilityHexadTest() {

        int[] block = new int[] { 0, 0, 0, 0, 0, 0 };

        cipher.hexad(block, Km, Kr, 0);
        cipher.hexad(block, Km, Kr, 6);
        cipher.hexadInv(block, Km, Kr, 12);
        cipher.hexadInv(block, Km, Kr, 18);

        assertArrayEquals(new int[] { 957446831, 381592354, 824238758, -1875623348, -787243285, -283567031 }, block);

        cipher.hexad(block, Km, Kr, 18);
        cipher.hexad(block, Km, Kr, 12);
        cipher.hexadInv(block, Km, Kr, 6);
        cipher.hexadInv(block, Km, Kr, 0);

        assertArrayEquals(new int[] {0,0,0,0,0,0}, block);
    }

}

