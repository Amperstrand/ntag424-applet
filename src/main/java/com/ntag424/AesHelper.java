package com.ntag424;

// AES-128 CBC helpers, ISO7816 padding, and session IV derivation.
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

public final class AesHelper {
    private static final byte[] ZERO_IV = new byte[16];

    private final Cipher cipherEnc;
    private final Cipher cipherDec;
    private final AESKey workKey;
    private final CryptoWork work;

    public AesHelper(CryptoWork work) {
        this.work = work;
        cipherEnc = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        cipherDec = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        workKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
    }

    public void setKey(byte[] key, short off) {
        workKey.setKey(key, off);
    }

    public void encryptBlock(byte[] in, short inOff, byte[] out, short outOff) {
        cipherEnc.init(workKey, Cipher.MODE_ENCRYPT, ZERO_IV, (short) 0, (short) 16);
        cipherEnc.doFinal(in, inOff, (short) 16, out, outOff);
    }

    public void decryptBlock(byte[] in, short inOff, byte[] out, short outOff) {
        cipherDec.init(workKey, Cipher.MODE_DECRYPT, ZERO_IV, (short) 0, (short) 16);
        cipherDec.doFinal(in, inOff, (short) 16, out, outOff);
    }

    public short encryptCbc(byte[] in, short inOff, short inLen, byte[] out, short outOff) {
        cipherEnc.init(workKey, Cipher.MODE_ENCRYPT, ZERO_IV, (short) 0, (short) 16);
        return cipherEnc.doFinal(in, inOff, inLen, out, outOff);
    }

    public short decryptCbc(byte[] in, short inOff, short inLen, byte[] out, short outOff) {
        cipherDec.init(workKey, Cipher.MODE_DECRYPT, ZERO_IV, (short) 0, (short) 16);
        return cipherDec.doFinal(in, inOff, inLen, out, outOff);
    }

    private void deriveIv(byte[] prefix, short prefixOff, byte[] ti, short tiOff,
                         short cmdCtr, byte[] ivOut, short ivOutOff) {
        byte[] ivInput = work.block16;
        UtilCompat.arrayFillNonAtomic(ivInput, (short) 0, (short) 16, (byte) 0);
        UtilCompat.arrayCopy(prefix, prefixOff, ivInput, (short) 0, (short) 2);
        UtilCompat.arrayCopy(ti, tiOff, ivInput, (short) 2, (short) 4);
        ivInput[6] = UtilCompat.getByteLSB(cmdCtr, (byte) 0);
        ivInput[7] = UtilCompat.getByteLSB(cmdCtr, (byte) 1);
        encryptBlock(ivInput, (short) 0, ivOut, ivOutOff);
    }

    public short encryptSession(byte[] prefix, short prefixOff, byte[] ti, short tiOff,
                                short cmdCtr, byte[] in, short inOff, short inLen,
                                byte[] out, short outOff) {
        deriveIv(prefix, prefixOff, ti, tiOff, cmdCtr, work.sessionKey, (short) 0);
        short paddedLen;
        if (inLen == 0) {
            out[outOff] = (byte) 0x80;
            paddedLen = (short) 16;
            UtilCompat.arrayFillNonAtomic(out, (short) (outOff + 1), (short) 15, (byte) 0);
        } else {
            paddedLen = isoPad(in, inOff, inLen, out, outOff);
        }
        cipherEnc.init(workKey, Cipher.MODE_ENCRYPT, work.sessionKey, (short) 0, (short) 16);
        return cipherEnc.doFinal(out, outOff, paddedLen, out, outOff);
    }

    public short decryptSession(byte[] prefix, short prefixOff, byte[] ti, short tiOff,
                                short cmdCtr, byte[] in, short inOff, short inLen,
                                byte[] out, short outOff) {
        deriveIv(prefix, prefixOff, ti, tiOff, cmdCtr, work.sessionKey, (short) 0);
        cipherDec.init(workKey, Cipher.MODE_DECRYPT, work.sessionKey, (short) 0, (short) 16);
        return cipherDec.doFinal(in, inOff, inLen, out, outOff);
    }

    public static short isoUnpad(byte[] in, short inOff, short inLen) {
        for (short i = (short) (inOff + inLen - 1); i >= inOff; i--) {
            if (in[i] == (byte) 0x80) {
                return (short) (i - inOff);
            }
            if (in[i] != 0) {
                return inLen;
            }
        }
        return inLen;
    }

    public static short isoPad(byte[] in, short inOff, short inLen, byte[] out, short outOff) {
        UtilCompat.arrayCopy(in, inOff, out, outOff, inLen);
        short pos = (short) (outOff + inLen);
        out[pos++] = (byte) 0x80;
        while ((short) (pos - outOff) % 16 != 0) {
            out[pos++] = 0;
        }
        return (short) (pos - outOff);
    }

    public static void rotateLeft(byte[] buf, short off, short len) {
        byte first = buf[off];
        for (short i = 0; i < (short) (len - 1); i++) {
            buf[(short) (off + i)] = buf[(short) (off + i + 1)];
        }
        buf[(short) (off + len - 1)] = first;
    }

    public static void rotateRight(byte[] buf, short off, short len) {
        byte last = buf[(short) (off + len - 1)];
        for (short i = (short) (len - 1); i > 0; i--) {
            buf[(short) (off + i)] = buf[(short) (off + i - 1)];
        }
        buf[off] = last;
    }

    public static void xorBlock(byte[] a, short aOff, byte[] b, short bOff) {
        for (short i = 0; i < 16; i++) {
            a[(short) (aOff + i)] ^= b[(short) (bOff + i)];
        }
    }
}
