package uk.ac.nottingham.cryptography.CAST;

import org.junit.jupiter.api.*;
import uk.ac.nottingham.cryptography.CASTCipher;
import uk.ac.nottingham.cryptography.CASTKeySet;
import uk.ac.nottingham.cryptography.HexUtils;

import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertEquals;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class VariableKeyTests {
    private final CASTCipher cipher = ServiceLoader.load(CASTCipher.class).findFirst().orElseThrow();

    private static final byte[] key128;
    private static final byte[] key192;
    private static final byte[] key256;
    private static final byte[] key384;

    static {
        key128 = new byte[16];
        key192 = new byte[24];
        key256 = new byte[32];
        key384 = new byte[48];

        for (int i = 0; i < 48; i++) {
            key384[i] = (byte)(0x2D ^ i);
        }

        for (int i = 0; i < 32; i++) {
            key256[i] = (byte)(0xBF ^ i);
        }

        for (int i = 0; i < 24; i++) {
            key192[i] = (byte)(0x04 ^ i);
        }

        for (int i = 0; i < 16; i++) {
            key128[i] = (byte)(0xA1 ^ i);
        }
    }

    @Test
    @Order(0)
    void key128Test() {
        CASTKeySet T = cipher.generateScheduleKeys(12, 4);
        CASTKeySet K = cipher.generateRoundKeys(T, key128, 12, 4);

        int[] Km = K.getM();
        int[] Kr = K.getR();

        int xm = HexUtils.XORArray(Km);
        int xr = HexUtils.XORArray(Kr);

        int sm = HexUtils.SumArray(Km);
        int sr = HexUtils.SumArray(Kr);

        // Length
        assertEquals(72, Km.length);
        assertEquals(72, Kr.length);

        // Contents check
        assertEquals(0xD51768A, xm);
        assertEquals(0x1C, xr);
        assertEquals(0x4589E97A, sm);
        assertEquals(0x446, sr);
    }

    @Test
    @Order(1)
    void key192Test() {
        CASTKeySet T = cipher.generateScheduleKeys(12, 4);
        CASTKeySet K = cipher.generateRoundKeys(T, key192, 12, 4);

        int[] Km = K.getM();
        int[] Kr = K.getR();

        int xm = HexUtils.XORArray(Km);
        int xr = HexUtils.XORArray(Kr);

        int sm = HexUtils.SumArray(Km);
        int sr = HexUtils.SumArray(Kr);

        // Length
        assertEquals(72, Km.length);
        assertEquals(72, Kr.length);

        // Contents check
        assertEquals(0x63DA7FF1, xm);
        assertEquals(0xD, xr);
        assertEquals(0x3D500DC9, sm);
        assertEquals(0x4D9, sr);
    }

    @Test
    @Order(2)
    void key256Test() {
        CASTKeySet T = cipher.generateScheduleKeys(12, 4);
        CASTKeySet K = cipher.generateRoundKeys(T, key256, 12, 4);

        int[] Km = K.getM();
        int[] Kr = K.getR();

        int xm = HexUtils.XORArray(Km);
        int xr = HexUtils.XORArray(Kr);

        int sm = HexUtils.SumArray(Km);
        int sr = HexUtils.SumArray(Kr);

        // Length
        assertEquals(72, Km.length);
        assertEquals(72, Kr.length);

        // Contents check
        assertEquals(0x7CE3CC9D, xm);
        assertEquals(0x12, xr);
        assertEquals(0xDC2898E1, sm);
        assertEquals(0x40A, sr);
    }

    @Test
    @Order(3)
    void key384Test() {
        CASTKeySet T = cipher.generateScheduleKeys(12, 4);
        CASTKeySet K = cipher.generateRoundKeys(T, key384, 12, 4);

        int[] Km = K.getM();
        int[] Kr = K.getR();

        int xm = HexUtils.XORArray(Km);
        int xr = HexUtils.XORArray(Kr);

        int sm = HexUtils.SumArray(Km);
        int sr = HexUtils.SumArray(Kr);

        // Length
        assertEquals(72, Km.length);
        assertEquals(72, Kr.length);

        // Contents check
        assertEquals(0xC05293CC, xm);
        assertEquals(0x7, xr);
        assertEquals(0x2ED6B7EE, sm);
        assertEquals(0x453, sr);
    }


}

