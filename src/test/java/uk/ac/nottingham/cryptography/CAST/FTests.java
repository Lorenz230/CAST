package uk.ac.nottingham.cryptography.CAST;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import uk.ac.nottingham.cryptography.CASTCipher;

import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertEquals;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class FTests {
    private final CASTCipher cipher = ServiceLoader.load(CASTCipher.class).findFirst().orElseThrow();

    private static final int[] testData = new int[] {
            0,
            1,
            0xFF,
            0xA1B2C3D4,
            0x00F40ABA,
            0x01020304,
            0xFEDCBA98,
            0x12345678
    };

    private static final int[] testTm = new int[] {
            0,
            1,
            0x00123000,
            0x80000000,
            0xCA423B20,
            0x55555555,
            0xFFFFFFFF,
            0xDB68Af3C
    };

    private static final int[] testTr = new int[] {
            0,
            1,
            17,
            14,
            30,
            29,
            4,
            6,
    };

    @Test
    void f1Test() {
        int[] expectedOutput = new int[] {
            0x3F9E9220,
            0xEC3B09DB,
            0x06A42F27,
            0xB1FC1D8E,
            0xB560C77B,
            0x311271CE,
            0xAFEFF814,
            0xCE6D5AE5
        };

        for (int i = 0; i < 8; i++) {
            int result = cipher.f1(testData[i], testTm[i], testTr[i]);
            assertEquals(expectedOutput[i], result);
        }
    }

    @Test
    void f2Test() {
        int[] expectedOutput = new int[] {
                0x0279F6A0,
                0x0279F6A0,
                0x9E7C2F17,
                0x08880094,
                0x1B1F2E49,
                0x7A0D8A77,
                0x29104614,
                0x99ED77AA
        };

        for (int i = 0; i < 8; i++) {
            int result = cipher.f2(testData[i], testTm[i], testTr[i]);
            assertEquals(expectedOutput[i], result);
        }
        int g = 0;
    }


    @Test
    void f3Test() {
        int[] expectedOutput = new int[] {
                0x40418F08,
                0x40418F08,
                0x46A0A60E,
                0x9690D6A0,
                0x83E7A21C,
                0x84CE69E6,
                0xDB4DE2DE,
                0x5B338A4C
        };

        for (int i = 0; i < 8; i++) {
            int result = cipher.f3(testData[i], testTm[i], testTr[i]);
            assertEquals(expectedOutput[i], result);
        }
    }

    @Test
    void f4Test() {
        int[] expectedOutput = new int[] {
                0x20180E60,
                0x20180E60,
                0xFE681DB2,
                0x930AC3FE,
                0x7EDD9A84,
                0x73FDCF04,
                0xD947C1EE,
                0x506301AA
        };

        for (int i = 0; i < 8; i++) {
            int result = cipher.f4(testData[i], testTm[i], testTr[i]);
            assertEquals(expectedOutput[i], result);
        }
    }

    @Test
    void f5Test() {
        int[] expectedOutput = new int[] {
                0x39E7F620,
                0xE6846DDB,
                0x05F42BA7,
                0x0674008A,
                0x99A3B52B,
                0x11058DAA,
                0xCF37A910,
                0x8C6C8BD9
        };

        for (int i = 0; i < 8; i++) {
            int result = cipher.f5(testData[i], testTm[i], testTr[i]);
            assertEquals(expectedOutput[i], result);
        }
    }

    @Test
    void f6Test() {
        int[] expectedOutput = new int[] {
                0x5F988B08,
                0x5F988B08,
                0xE54CC68D,
                0xC3E19FD2,
                0x8B196929,
                0xE5E213D3,
                0xD834AD5A,
                0x92F18BA2
        };

        for (int i = 0; i < 8; i++) {
            int result = cipher.f6(testData[i], testTm[i], testTr[i]);
            assertEquals(expectedOutput[i], result);
        }
    }

}

