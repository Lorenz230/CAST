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
public class ScheduleKeyTests {
    private final CASTCipher cipher = ServiceLoader.load(CASTCipher.class).findFirst().orElseThrow();

    @Test
    void firstValueTest() {
        final CASTKeySet T = cipher.generateScheduleKeys(1, 1);
        int[] Tm = T.getM();
        int[] Tr = T.getR();

        assertEquals(12, Tm.length);
        assertEquals(12, Tr.length);
        assertEquals(0x5A827999, Tm[0]);
        assertEquals(19, Tr[0]);
    }

    @Test
    void singleRoundSetTest() {
        final CASTKeySet T = cipher.generateScheduleKeys(1, 1);
        int[] Tm = T.getM();
        int[] Tr = T.getR();

        int xr = HexUtils.XORArray(Tr);
        int xm = HexUtils.XORArray(Tm);
        int sr = HexUtils.SumArray(Tr);
        int sm = HexUtils.SumArray(Tm);

        // Length
        assertEquals(12, Tm.length);
        assertEquals(12, Tr.length);

        // Totals
        assertEquals(0xC, xr);
        assertEquals(0x2F9C7F7C, xm);
        assertEquals(0xC6, sr);
        assertEquals(0xD24C72AE, sm);

        // Final value
        assertEquals(14, Tr[11]);
        assertEquals(0x1DDF9984, Tm[11]);
    }

    @Test
    void multiRoundSetTest() {
        final CASTKeySet T = cipher.generateScheduleKeys(3, 1);
        int[] Tm = T.getM();
        int[] Tr = T.getR();

        int xr = HexUtils.XORArray(Tr);
        int xm = HexUtils.XORArray(Tm);
        int sr = HexUtils.SumArray(Tr);
        int sm = HexUtils.SumArray(Tm);

        // Length
        assertEquals(36, Tm.length);
        assertEquals(36, Tr.length);

        // Totals
        assertEquals(4, xr);
        assertEquals(0x6D85E464, xm);
        assertEquals(0x222, sr);
        assertEquals(0x86A2F7BA, sm);

        // Final value
        assertEquals(6, Tr[35]);
        assertEquals(0x824DB09C, Tm[35]);
    }

    @Test
    void multiDodecadSetTest() {
        final CASTKeySet T = cipher.generateScheduleKeys(1, 4);
        int[] Tm = T.getM();
        int[] Tr = T.getR();

        int xr = HexUtils.XORArray(Tr);
        int xm = HexUtils.XORArray(Tm);
        int sr = HexUtils.SumArray(Tr);
        int sm = HexUtils.SumArray(Tm);

        // Length
        assertEquals(48, Tm.length);
        assertEquals(48, Tr.length);

        // Totals
        assertEquals(16, xr);
        assertEquals(0x8B7DF1D0, xm);
        assertEquals(0x2F8, sr);
        assertEquals(0x68AD0A18, sm);

        // Final value
        assertEquals(18, Tr[47]);
        assertEquals(0xB484BC28, Tm[47]);
    }

    @Test
    void fullTest() {
        final CASTKeySet T = cipher.generateScheduleKeys(12, 6);
        int[] Tm = T.getM();
        int[] Tr = T.getR();

        int xr = HexUtils.XORArray(Tr);
        int xm = HexUtils.XORArray(Tm);
        int sr = HexUtils.SumArray(Tr);
        int sm = HexUtils.SumArray(Tm);

        // Length
        assertEquals(864, Tm.length);
        assertEquals(864, Tr.length);

        // Totals
        assertEquals(0, xr);
        assertEquals(0x0C7205A0, xm);
        assertEquals(0x3450, sr);
        assertEquals(0x8897B6B0, sm);

        // Final value
        assertEquals(2, Tr[863]);
        assertEquals(0xB23CD58, Tm[863]);
    }



}

