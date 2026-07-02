package com.ntag424;

// AES-CMAC (NIST SP 800-38B) with 8-byte truncated MAC for EV2/SDM.
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

public final class AesCmac {
    private static final byte[] ZERO = new byte[16];
    private static final byte[] RB = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, (byte) 0x87
    };

    private final Cipher cipher;
    private final AESKey key;
    private final byte[] k1;
    private final byte[] k2;
    private final byte[] block;
    private final CryptoWork work;

    public AesCmac(CryptoWork work) {
        this.work = work;
        cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        k1 = new byte[16];
        k2 = new byte[16];
        block = new byte[16];
    }

    public void setKey(byte[] keyData, short off) {
        key.setKey(keyData, off);
        generateSubkeys();
    }

    public void compute(byte[] msg, short msgOff, short msgLen, byte[] mac, short macOff) {
        short blocks = (short) ((short) (msgLen + 15) / 16);
        boolean complete = (msgLen != 0) && ((msgLen % 16) == 0);

        if (blocks == 0) {
            blocks = 1;
            complete = false;
        }

        short lastBlockStart = (short) (msgOff + (short) ((blocks - 1) * 16));
        short lastBlockLen = (short) (msgLen - (short) ((blocks - 1) * 16));

        UtilCompat.arrayFillNonAtomic(block, (short) 0, (short) 16, (byte) 0);
        if (complete) {
            UtilCompat.arrayCopy(msg, lastBlockStart, block, (short) 0, (short) 16);
            AesHelper.xorBlock(block, (short) 0, k1, (short) 0);
        } else {
            if (lastBlockLen > 0) {
                UtilCompat.arrayCopy(msg, lastBlockStart, block, (short) 0, lastBlockLen);
            }
            block[lastBlockLen] = (byte) 0x80;
            AesHelper.xorBlock(block, (short) 0, k2, (short) 0);
        }

        UtilCompat.arrayFillNonAtomic(mac, macOff, (short) 16, (byte) 0);
        for (short i = 0; i < (short) (blocks - 1); i++) {
            short off = (short) (msgOff + i * 16);
            for (short j = 0; j < 16; j++) {
                mac[(short) (macOff + j)] ^= msg[(short) (off + j)];
            }
            cipher.init(key, Cipher.MODE_ENCRYPT, ZERO, (short) 0, (short) 16);
            cipher.doFinal(mac, macOff, (short) 16, mac, macOff);
        }

        for (short j = 0; j < 16; j++) {
            mac[(short) (macOff + j)] ^= block[j];
        }
        cipher.init(key, Cipher.MODE_ENCRYPT, ZERO, (short) 0, (short) 16);
        cipher.doFinal(mac, macOff, (short) 16, mac, macOff);
    }

    public static void shortenCmac(byte[] full, short fullOff, byte[] shortMac, short shortOff) {
        for (short i = 0; i < 8; i++) {
            shortMac[(short) (shortOff + i)] = full[(short) (fullOff + 1 + i * 2)];
        }
    }

    private void generateSubkeys() {
        byte[] l = work.sv32;
        cipher.init(key, Cipher.MODE_ENCRYPT, ZERO, (short) 0, (short) 16);
        cipher.doFinal(ZERO, (short) 0, (short) 16, l, (short) 0);

        boolean msb = (l[0] & (byte) 0x80) != 0;
        leftShift(l, k1);
        if (msb) {
            AesHelper.xorBlock(k1, (short) 0, RB, (short) 0);
        }

        msb = (k1[0] & (byte) 0x80) != 0;
        leftShift(k1, k2);
        if (msb) {
            AesHelper.xorBlock(k2, (short) 0, RB, (short) 0);
        }
    }

    private static void leftShift(byte[] in, byte[] out) {
        byte carry = 0;
        for (short i = 15; i >= 0; i--) {
            byte nextCarry = (byte) ((in[i] & (byte) 0x80) != 0 ? 1 : 0);
            out[i] = (byte) ((in[i] << 1) | carry);
            carry = nextCarry;
        }
    }
}
