package uk.ac.nottingham.cryptography.CAST;

import org.junit.jupiter.api.*;
import uk.ac.nottingham.cryptography.CASTCipher;
import uk.ac.nottingham.cryptography.CASTKeySet;
import uk.ac.nottingham.cryptography.HexUtils;

import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class RoundKeyTests {
    private final CASTCipher cipher = ServiceLoader.load(CASTCipher.class).findFirst().orElseThrow();

    @BeforeAll
    void requiresT() {
        final CASTKeySet T = cipher.generateScheduleKeys(12, 4);
        int[] Tm = T.getM();
        int[] Tr = T.getR();

        int xr = HexUtils.XORArray(Tr);
        int xm = HexUtils.XORArray(Tm);
        int sr = HexUtils.SumArray(Tr);
        int sm = HexUtils.SumArray(Tm);

        // Length
        assumeTrue(Tm.length == 576);
        assumeTrue(Tr.length == 576);

        // Totals
        assumeTrue(0 == xr);
        assumeTrue(0x9022F7C0 == xm);
        assumeTrue(0x22E0 == sr);
        assumeTrue(0x8CD80B20 == sm);

        // Final value
        assumeTrue(2 == Tr[575]);
        assumeTrue(0x55FAB838 == Tm[575]);
    }

    @Test
    void firstValueTest1() {
        // Using a key of all zeros
        CASTKeySet T = cipher.generateScheduleKeys(1, 1);
        CASTKeySet K = cipher.generateRoundKeys(T, new byte[48], 1,  1);

        int[] Km = K.getM();
        int[] Kr = K.getR();

        assertEquals(6, Km.length);
        assertEquals(6, Kr.length);

        assertEquals(0xED8CAEB7, Km[0]);
        assertEquals(31, Kr[0]);
    }

    @Test
    void firstValueTest2() {
        // Using a key of all zeros
        CASTKeySet T = cipher.generateScheduleKeys(1, 2);
        CASTKeySet K = cipher.generateRoundKeys(T, new byte[48], 1,  2);

        int[] Km = K.getM();
        int[] Kr = K.getR();

        assertEquals(6, Km.length);
        assertEquals(6, Kr.length);

        assertEquals(0xCAF397BF, Km[0]);
        assertEquals(7, Kr[0]);
    }

    @Test
    void firstValueTest3() {
        // Using a key of all zeros
        CASTKeySet T = cipher.generateScheduleKeys(1, 4);
        CASTKeySet K = cipher.generateRoundKeys(T, new byte[48], 1,  4);

        int[] Km = K.getM();
        int[] Kr = K.getR();

        assertEquals(6, Km.length);
        assertEquals(6, Kr.length);

        assertEquals(0x170689C6, Km[0]);
        assertEquals(1, Kr[0]);
    }

    @Test
    void firstValueTest4() {
        // Using a key of all zeros
        byte[] key = new byte[48];
        key[0] = (byte)0x80;
        key[23] = 1;

        CASTKeySet T = cipher.generateScheduleKeys(1, 4);
        CASTKeySet K = cipher.generateRoundKeys(T, key, 1, 4);

        int[] Km = K.getM();
        int[] Kr = K.getR();

        assertEquals(6, Km.length);
        assertEquals(6, Kr.length);

        assertEquals(0xB64A8B9A, Km[0]);
        assertEquals(3, Kr[0]);
    }

    @Test
    void doubleRoundTest1() {
        CASTKeySet T = cipher.generateScheduleKeys(12, 2);
        CASTKeySet K = cipher.generateRoundKeys(T, new byte[48], 2, 2);

        int[] Km = K.getM();
        int[] Kr = K.getR();

        int xm = HexUtils.XORArray(Km);
        int xr = HexUtils.XORArray(Kr);

        int sm = HexUtils.SumArray(Km);
        int sr = HexUtils.SumArray(Kr);

        // Length
        assertEquals(12, Km.length);
        assertEquals(12, Kr.length);

        // Contents check
        assertEquals(0xF0716562, xm);
        assertEquals(15, xr);
        assertEquals(0xCDFF55AE, sm);
        assertEquals(0xC9, sr);
    }

    @Test
    void doubleRoundTest2() {
        CASTKeySet T = cipher.generateScheduleKeys(12, 4);
        CASTKeySet K = cipher.generateRoundKeys(T, new byte[48], 2, 4);

        int[] Km = K.getM();
        int[] Kr = K.getR();

        int xm = HexUtils.XORArray(Km);
        int xr = HexUtils.XORArray(Kr);

        int sm = HexUtils.SumArray(Km);
        int sr = HexUtils.SumArray(Kr);

        // Length
        assertEquals(12, Km.length);
        assertEquals(12, Kr.length);

        // Contents check
        assertEquals(0xFF2D72F2, xm);
        assertEquals(0x5, xr);
        assertEquals(0x82B571F8, sm);
        assertEquals(0xB9, sr);
    }

    @Test
    void quadRoundTest() {
        byte [] key = new byte[48];
        for (int i = 0; i < 24; i++) {
            key[i] = (byte)(i * 3);
        }

        CASTKeySet T = cipher.generateScheduleKeys(4, 4);
        CASTKeySet K = cipher.generateRoundKeys(T, key, 4, 4);

        int[] Km = K.getM();
        int[] Kr = K.getR();

        int xm = HexUtils.XORArray(Km);
        int xr = HexUtils.XORArray(Kr);

        int sm = HexUtils.SumArray(Km);
        int sr = HexUtils.SumArray(Kr);

        // Length
        assertEquals(24, Km.length);
        assertEquals(24, Kr.length);

        // Contents check
        assertEquals(0xFE1A1374, xm);
        assertEquals(0x16, xr);
        assertEquals(0xB6FFC102, sm);
        assertEquals(0x140, sr);
    }

    @Test
    void longDodecadTest() {
        byte [] key = new byte[48];
        for (int i = 0; i < 24; i++) {
            key[i] = (byte)(i * 3);
        }

        CASTKeySet T = cipher.generateScheduleKeys(4, 24);
        CASTKeySet K = cipher.generateRoundKeys(T, key, 4, 24);

        int[] Km = K.getM();
        int[] Kr = K.getR();

        int xm = HexUtils.XORArray(Km);
        int xr = HexUtils.XORArray(Kr);

        int sm = HexUtils.SumArray(Km);
        int sr = HexUtils.SumArray(Kr);

        // Length
        assertEquals(24, Km.length);
        assertEquals(24, Kr.length);

        // Contents check
        assertEquals(0x76A7E028, xm);
        assertEquals(0x11, xr);
        assertEquals(0x9808D71E, sm);
        assertEquals(0x181, sr);
    }

    @Test
    void fullTest() {
        int[] expectedM = new int[] {
                0x170689C6,0xC72FAC8A,0x95D465D1,0x7C34CB0B,0xCC8EB88E,0xC317B77D,0xEEA31189,0x142E7E37,0x20569817,
                0x6220A056,0xE78439FE,0x96029896,0x1A82B136,0xA7F8F99B,0x0C3B596C,0xF7D2EBA2,0x184F7E45,0xDEC44FC7,
                0xFB62BF63,0x417CF031,0x338D67DF,0x96044541,0x0493B837,0x4BD08CF8,0xBDD025C3,0x7A4235CB,0x1239AC6B,
                0xCAB7A290,0x76A7734F,0xDEFA172E,0xAB916FE5,0x79B74AFC,0xDDB9DB21,0x17161BDE,0x2EF73A31,0xA791806A,
                0xD75D5C69,0xD7833CB4,0x3D8BE4B0,0x98A12F67,0xCDDB22EB,0xD7ADA3FE,0xD6FBCD8E,0x4D16EFEA,0xB9C5B9B3,
                0xC12360F3,0x8C91A68F,0xD45566AA,0x6AFBDBE0,0x921B90F2,0xF80F231A,0xE1B3B543,0xE9487EAB,0xD9F8752A,
                0xA25D8EA3,0xB40989B6,0xDCF4F0EF,0xD3E2F928,0x518C68B2,0x083EC288,0x999C1B0A,0x93C54D6F,0xE1B65890,
                0x506ED1EA,0x7E1B8CFB,0x24FD4FDB,0xB5D260DF,0x6B50CB2A,0x6DC6CADE,0xA694066F,0x6BC0157C,0x9E1AB600
        };

        int[] expectedR = new int[] {
                0x01,0x03,0x1A,0x19,0x0C,0x1B,0x1D,0x04,0x18,0x00,0x08,0x1A,0x0D,0x17,0x1C,0x11,0x05,0x03,0x16,0x15,
                0x0D,0x1F,0x03,0x14,0x03,0x1D,0x05,0x1B,0x19,0x0A,0x0F,0x01,0x12,0x0A,0x09,0x0E,0x04,0x18,0x1B,0x03,
                0x02,0x14,0x08,0x09,0x07,0x15,0x0B,0x1F,0x1C,0x08,0x03,0x01,0x09,0x0F,0x14,0x0F,0x06,0x1C,0x15,0x02,
                0x06,0x0D,0x0D,0x1E,0x1E,0x0D,0x1F,0x07,0x15,0x02,0x13,0x0A
        };

        CASTKeySet T = cipher.generateScheduleKeys(12, 4);
        CASTKeySet K = cipher.generateRoundKeys(T, new byte[48], 12, 4);

        int[] Km = K.getM();
        int[] Kr = K.getR();

        assertArrayEquals(expectedM, Km);
        assertArrayEquals(expectedR, Kr);
    }
}

