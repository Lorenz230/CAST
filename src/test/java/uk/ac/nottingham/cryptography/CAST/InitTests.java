package uk.ac.nottingham.cryptography.CAST;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import uk.ac.nottingham.cryptography.CASTCipher;
import uk.ac.nottingham.cryptography.CASTKeySet;
import uk.ac.nottingham.cryptography.HexUtils;

import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertEquals;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class InitTests {
    private final CASTCipher cipher = ServiceLoader.load(CASTCipher.class).findFirst().orElseThrow();

    private static final byte[] keyA;
    private static final byte[] keyB;

    static {
        keyA = new byte[48];
        keyB = new byte[48];

        for (int i = 0; i < 48; i++) {
            keyA[i] = (byte) i;
            keyB[i] = (byte) (i * 7);
        }
    }

    @Test
    void singleInitTest1() {
        cipher.initialise(keyA);
        CASTKeySet K = cipher.getK();

        int[] Km = K.getM();
        int[] Kr = K.getR();

        int xr = HexUtils.XORArray(Kr);
        int xm = HexUtils.XORArray(Km);
        int sr = HexUtils.SumArray(Kr);
        int sm = HexUtils.SumArray(Km);

        // Length
        assertEquals(72, Km.length);
        assertEquals(72, Kr.length);

        // Totals
        assertEquals(0x13, xr);
        assertEquals(0xED837741, xm);
        assertEquals(0x403, sr);
        assertEquals(0xB44316C5, sm);

        // Final value
        assertEquals(16, Kr[71]);
        assertEquals(0x177DC53C, Km[71]);

    }

    @Test
    void singleInitTest2() {
        cipher.initialise(keyB);
        CASTKeySet K = cipher.getK();

        int[] Km = K.getM();
        int[] Kr = K.getR();

        int xr = HexUtils.XORArray(Kr);
        int xm = HexUtils.XORArray(Km);
        int sr = HexUtils.SumArray(Kr);
        int sm = HexUtils.SumArray(Km);

        // Length
        assertEquals(72, Km.length);
        assertEquals(72, Kr.length);

        // Totals
        assertEquals(0xB, xr);
        assertEquals(0x212AD443, xm);
        assertEquals(0x43F, sr);
        assertEquals(0xF09BE5E9, sm);

        // Final value
        assertEquals(4, Kr[71]);
        assertEquals(0x8A481E1D, Km[71]);
    }

    @Test
    void repeatInitTest() {
        byte[] key = new byte[48];
        int xr = 0, xm = 0, sr = 0, sm = 0;
        int[] Km, Kr;

        for (int i = 0; i < 10; i++) {
            key[47]++;
            cipher.initialise(key);

            Km = cipher.getK().getM();
            Kr = cipher.getK().getR();

            xr ^= HexUtils.XORArray(Kr);
            xm ^= HexUtils.XORArray(Km);
            sr ^= HexUtils.SumArray(Kr);
            sm ^= HexUtils.SumArray(Km);
        }

        CASTKeySet K = cipher.getK();
        Km = K.getM();
        Kr = K.getR();

        // Length
        assertEquals(72, Km.length);
        assertEquals(72, Kr.length);

        // Totals
        assertEquals(0x9, xr);
        assertEquals(0xD8E4501D, xm);
        assertEquals(0xB1, sr);
        assertEquals(0xDEC15879, sm);

        // Final value
        assertEquals(18, Kr[71]);
        assertEquals(0x78F69B60, Km[71]);
    }
}

