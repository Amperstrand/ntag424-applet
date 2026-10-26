package com.ntag424;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/** Independent AES-CMAC (RFC 4493) for tests — NOT the applet's crypto. */
public final class TestCrypto {
    private TestCrypto() {}

    static byte[] aes(byte[] key, byte[] in) throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        return c.doFinal(in);
    }

    static byte[] cmac(byte[] key, byte[] msg) throws Exception {
        byte[] l = aes(key, new byte[16]);
        byte[] k1 = shift(l, false);
        byte[] k2 = shift(k1, false);
        byte[] m;
        int n;
        if (msg.length == 0) {
            m = new byte[16];
            m[0] = (byte) 0x80;
            xorIn(m, 0, k2);
            n = 1;
        } else {
            n = (msg.length + 15) / 16;
            boolean complete = msg.length % 16 == 0;
            int blocks = complete ? n : n; // last block padded below
            m = new byte[n * 16];
            System.arraycopy(msg, 0, m, 0, msg.length);
            if (!complete) {
                m[msg.length] = (byte) 0x80;
                xorIn(m, (n - 1) * 16, k2);
            } else {
                xorIn(m, (n - 1) * 16, k1);
            }
        }
        byte[] x = new byte[16];
        for (int i = 0; i < n; i++) {
            byte[] y = xor(x, 0, m, i * 16);
            x = aes(key, y);
        }
        return x;
    }

    static byte[] cmac8(byte[] key, byte[] msg) throws Exception {
        // NTAG424 CMt truncation (AesCmac.shortenCmac): odd-index bytes
        // 1,3,5,..,15 of the full CMAC.
        byte[] full = cmac(key, msg);
        byte[] out = new byte[8];
        for (int i = 0; i < 8; i++) out[i] = full[1 + i * 2];
        return out;
    }

    private static byte[] shift(byte[] b, boolean unused) {
        byte[] out = new byte[16];
        int carry = 0;
        for (int i = 15; i >= 0; i--) {
            out[i] = (byte) ((b[i] << 1) | carry);
            carry = (b[i] & 0x80) != 0 ? 1 : 0;
        }
        if ((b[0] & 0x80) != 0) out[15] ^= 0x87;
        return out;
    }

    static byte[] xor(byte[] a, int ao, byte[] b, int bo) {
        byte[] out = new byte[16];
        for (int i = 0; i < 16; i++) out[i] = (byte) (a[ao + i] ^ b[bo + i]);
        return out;
    }

    static void xorIn(byte[] a, int ao, byte[] k) {
        for (int i = 0; i < 16; i++) a[ao + i] ^= k[i];
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02X", x));
        return sb.toString();
    }

    static byte[] hexBytes(String h) {
        byte[] out = new byte[h.length() / 2];
        for (int i = 0; i < out.length; i++)
            out[i] = (byte) Integer.parseInt(h.substring(2 * i, 2 * i + 2), 16);
        return out;
    }

    static byte[] cmac8Pub(byte[] key, byte[] msg) throws Exception {
        return cmac8(key, msg);
    }

    /** RFC 4493 AES-CMAC test vectors. */
    static void selfTest() throws Exception {
        byte[] key = hexBytes("2B7E151628AED2A6ABF7158809CF4F3C");
        String[][] vectors = {
            {"", "BB1D6929E95937287FA37D129B756746"},
            {"6BC1BEE22E409F96E93D7E117393172A", "070A16B46B4D4144F79BDD9DD04A287C"},
            {"6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411",
             "DFA66747DE9AE63030CA32611497C827"},
        };
        for (String[] v : vectors) {
            byte[] mac = cmac(key, v[0].isEmpty() ? new byte[0] : hexBytes(v[0]));
            if (!hex(mac).toUpperCase().equals(v[1]))
                throw new AssertionError("RFC4493 vector failed: got " + hex(mac));
        }
    }
}
