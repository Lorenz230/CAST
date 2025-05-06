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
public class DodecadTests {
    private final CASTCipher cipher = ServiceLoader.load(CASTCipher.class).findFirst().orElseThrow();

    @Test
    void simpleBlockTest() {

        int[] block = new int[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
        int[] Tm = new int[] { 50, 49, 48, 47, 46, 45, 44, 43, 42, 41, 40, 39 };
        int[] Tr = new int[] { 1, 15, 6, 19, 31, 2, 15, 15, 12, 17, 21, 24 };

        int[] expectedOutput = new int[] {
                0x6ADE869B,
                0x5C512582,
                0x8277600A,
                0xD3E25CEB,
                0x4A44F9C5,
                0x3FEA197A,
                0xA1686BFA,
                0x798E43B0,
                0x23615244,
                0x71175903,
                0x3E23B68A,
                0xB8593339
        };

        cipher.dodecad(block, Tm, Tr, 0);
        assertArrayEquals(expectedOutput, block);
    }

    @Test
    void simpleBlockTest2() {

        int[] block = new int[] { 0x31, 0xFF34, 0x1123, 0x22129, 0x32848, 0xFFDA2, 0xBAC344, 0x12, 0xFA, 0x4454, 0xABAAC, 0xDAFF };
        int[] Tm = new int[] {
                0x6ADE869B,
                0x5C512582,
                0x8277600A,
                0xD3E25CEB,
                0x4A44F9C5,
                0x3FEA197A,
                0xA1686BFA,
                0x798E43B0,
                0x23615244,
                0x71175903,
                0x3E23B68A,
                0xB8593339
        };

        int[] Tr = new int[] { 23, 13, 0, 12, 19, 17, 24, 30, 5, 8, 8, 4};

        int[] expectedOutput = new int[] {
                0xF72C54D4,
                0xB717F7D5,
                0xAD25B1F6,
                0xDBEA4679,
                0x11E1AEE8,
                0xCEC07F03,
                0x6E6C6D93,
                0x77937ED3,
                0x3576B441,
                0x383D7F25,
                0xECFA9D6D,
                0x1E031820
        };

        cipher.dodecad(block, Tm, Tr, 0);
        assertArrayEquals(expectedOutput, block);
    }

    @Test
    void offsetBlockTest() {
        int[] block = new int[]{0x31, 0xFF34, 0x1123, 0x22129, 0x32848, 0xFFDA2, 0xBAC344, 0x12, 0xFA, 0x4454, 0xABAAC, 0xDAFF};
        int[] Tm = new int[]{
                0x6ADE869B,
                0x5C512582,
                0x8277600A,
                0xD3E25CEB,
                0x4A44F9C5,
                0x3FEA197A,
                0xA1686BFA,
                0x798E43B0,
                0x23615244,
                0x71175903,
                0x3E23B68A,
                0xB8593339,
                0xD3E25CEB,
                0x4A44F9C5,
                0x3FEA197A,
                0xA1686BFA,
                0x798E43B0,
                0x23615244,
                0xAD25B1F6,
                0xDBEA4679,
                0x11E1AEE8,
                0xCEC07F03,
                0x6E6C6D93,
                0x77937ED3,
                0x3576B441
        };

        int[] Tr = new int[]{23, 13, 0, 12, 19, 17, 24, 30, 5, 8, 8, 4,
                12, 30, 9, 8, 14, 16, 19, 20, 21, 22, 1, 4, 6, 8, 9};

        int[] offsets = new int[]{1, 5, 8};
        int[][] expectedOutput = new int[][]{
                {
                        0x8B128E67,
                        0x7923029D,
                        0x993B9638,
                        0x67759719,
                        0xF1621072,
                        0xAF2F66E8,
                        0x6215E8F5,
                        0x5A2B322D,
                        0x63ACDE95,
                        0x336D4924,
                        0x65631C72,
                        0xDA713F85
                },
                {
                        0x7ACBE466,
                        0xAEC4C961,
                        0x2A53A0A2,
                        0xC75BF567,
                        0x1A7DAA97,
                        0x292B0CAE,
                        0xCEEA86D0,
                        0x64F70823,
                        0x6E5FAE8A,
                        0x8C174BEF,
                        0x9533674A,
                        0x1C40EC59
                },
                {
                        0xAD905F0D,
                        0x7C5DCD73,
                        0x18EACBDC,
                        0x96995964,
                        0x7FDE8985,
                        0x36583CD2,
                        0xE237160E,
                        0x5AD4D4E1,
                        0x8B5FB427,
                        0x17B2E4F1,
                        0xC215EF21,
                        0xBBE29E4B
                },
        };

        int[] currentBlock = new int[12];
        for (int i = 0; i < 3; i++) {
            System.arraycopy(block, 0, currentBlock, 0, 12);
            cipher.dodecad(currentBlock, Tm, Tr, offsets[i]);
            assertArrayEquals(expectedOutput[i], currentBlock);
        }

    }

    @Test
    void repeatingTest() {

        int[] block = new int[] { 0x31, 0xFF34, 0x1123, 0x22129, 0x32848, 0xFFDA2, 0xBAC344, 0x12, 0xFA, 0x4454, 0xABAAC, 0xDAFF };
        int[] Tm = new int[] {
                0x6ADE869B,
                0x5C512582,
                0x8277600A,
                0xD3E25CEB,
                0x4A44F9C5,
                0x3FEA197A,
                0xA1686BFA,
                0x798E43B0,
                0x23615244,
                0x71175903,
                0x3E23B68A,
                0xB8593339
        };

        int[] Tr = new int[] { 23, 13, 0, 12, 19, 17, 24, 30, 5, 8, 8, 4};

        int[] expectedOutput = new int[] {
                0xF72C54D4,
                0xB717F7D5,
                0xAD25B1F6,
                0xDBEA4679,
                0x11E1AEE8,
                0xCEC07F03,
                0x6E6C6D93,
                0x77937ED3,
                0x3576B441,
                0x383D7F25,
                0xECFA9D6D,
                0x1E031820
        };

        int[] currentBlock = new int[12];

        for (int i = 0; i < 100; i++) {
            System.arraycopy(block, 0, currentBlock, 0, 12);
            cipher.dodecad(currentBlock, Tm, Tr, 0);
            assertArrayEquals(expectedOutput, currentBlock);
        }
    }

    @Test
    void iterativeTest() {
        int[] block = new int[12];

        int[] expectedOutput = new int[] {
                0xC2BF46EE,
                0x4C5D0CED,
                0xAAC36C1D,
                0xDFC943FB,
                0xD7712DC9,
                0x88210FA7,
                0x11DF7226,
                0x9195F535,
                0xCB3002F8,
                0x2411B5F3,
                0x7DAB524F,
                0xC4049686
        };

        int[] Tr = new int[10 * 12];
        int[] Tm = new int[10 * 12];

        for (int i = 1; i < 10 * 12; i++) {
            Tr[i] = (Tr[i-1] + 13) % 30;
            Tm[i] = Tm[i-1] + 0x1b;
        }

        for (int i = 0; i < 10; i++) {
            int n = i * 12;
            cipher.dodecad(block, Tm, Tr, n);
        }

        assertArrayEquals(expectedOutput, block);
    }

}

