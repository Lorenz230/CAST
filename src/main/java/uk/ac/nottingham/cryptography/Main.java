package uk.ac.nottingham.cryptography;

import java.util.Arrays;

public class Main {

    /**
     * Entry point when this program is run directly. Not used within
     * the coursework, but is available for those who would like to
     * test or debug themselves. Nothing in this file will be marked.
     *
     * @param args Command line arguments - not used in this coursework
     */
    public static void main(String[] args) {
        // Example: create cipher with a zero key, encrypt a zero block
        CASTCipher c384 = new CAST384();
        c384.initialise(new byte[48]);
        c384.encrypt(new byte[24]);

        // You can add testing code here
    }
}
