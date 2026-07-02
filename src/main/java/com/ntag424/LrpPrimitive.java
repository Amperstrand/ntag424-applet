package com.ntag424;

// AN12304 LRP: eval, LRICB (ELRP/DLRP), and LRP-CMAC (MAC_LRP).
public final class LrpPrimitive {
    private static final byte PLAINTEXT_COUNT = 16;
    private static final byte UPDATED_KEY_COUNT = 4;
    private static final short PLAINTEXT_BYTES = (short) (PLAINTEXT_COUNT * 16);
    private static final short UPDATED_KEY_BYTES = (short) (UPDATED_KEY_COUNT * 16);

    private static final byte[] CONST_AA = {
        (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA,
        (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA,
        (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA,
        (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA
    };
    private static final byte[] CONST_55 = {
        (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55,
        (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55,
        (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55,
        (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55
    };
    private static final byte[] ZERO = new byte[16];

    private final AesHelper aes;
    private final CryptoWork work;
    private final byte[] plaintexts;
    private final byte[] updatedKeys;
    private final byte[] k1;
    private final byte[] k2;
    private final byte[] sessMaster;
    private final byte[] padBlock;
    private final byte[] evalOut;
    private byte updatedKeyIndex;

    public LrpPrimitive(AesHelper aes, CryptoWork work) {
        this.aes = aes;
        this.work = work;
        plaintexts = new byte[PLAINTEXT_BYTES];
        updatedKeys = new byte[UPDATED_KEY_BYTES];
        k1 = new byte[16];
        k2 = new byte[16];
        sessMaster = new byte[16];
        padBlock = new byte[16];
        evalOut = new byte[16];
        updatedKeyIndex = 0;
    }

    public void setUpdatedKeyIndex(byte index) {
        updatedKeyIndex = index;
    }

    private void setKey(byte[] key, short off) {
        updatedKeyIndex = 0;
        generatePlaintexts(key, off);
        generateUpdatedKeys(key, off);
        generateSubkeys();
    }

    private void eval(byte[] iv, short ivOff, short ivNibbles, boolean finalize,
                     byte[] out, short outOff) {
        short ukOff = (short) ((short) (updatedKeyIndex & (short) 0xFF) * (short) 16);
        UtilCompat.arrayCopy(updatedKeys, ukOff, out, outOff, (short) 16);

        for (short i = 0; i < ivNibbles; i++) {
            byte nk;
            short byteIdx = (short) (ivOff + (short) (i / (short) 2));
            if ((i & 1) == 0) {
                nk = (byte) ((iv[byteIdx] >> 4) & 0x0F);
            } else {
                nk = (byte) (iv[byteIdx] & 0x0F);
            }
            short pOff = (short) ((short) (nk & (short) 0xFF) * (short) 16);
            aes.setKey(out, outOff);
            aes.encryptBlock(plaintexts, pOff, out, outOff);
        }

        if (finalize) {
            aes.setKey(out, outOff);
            aes.encryptBlock(ZERO, (short) 0, out, outOff);
        }
    }

    public short encryptLricb(byte[] counter, short ctrOff, short ctrNibbles,
                               boolean pad, byte[] in, short inOff, short inLen,
                               byte[] out, short outOff) {
        short dataLen;
        if (pad) {
            dataLen = AesHelper.isoPad(in, inOff, inLen, out, outOff);
        } else {
            UtilCompat.arrayCopy(in, inOff, out, outOff, inLen);
            dataLen = inLen;
        }

        short blocks = (short) (dataLen / (short) 16);
        for (short i = 0; i < blocks; i++) {
            short blockOff = (short) (outOff + (short) (i * (short) 16));
            eval(counter, ctrOff, ctrNibbles, true, work.block16, (short) 0);
            aes.setKey(work.block16, (short) 0);
            aes.encryptBlock(out, blockOff, out, blockOff);
            incCounter(counter, ctrOff, ctrNibbles);
        }
        return dataLen;
    }

    public short decryptLricb(byte[] counter, short ctrOff, short ctrNibbles,
                               boolean pad, byte[] in, short inOff, short inLen,
                               byte[] out, short outOff) {
        short blocks = (short) (inLen / (short) 16);
        for (short i = 0; i < blocks; i++) {
            short blockOff = (short) (inOff + (short) (i * (short) 16));
            short outBlock = (short) (outOff + (short) (i * (short) 16));
            eval(counter, ctrOff, ctrNibbles, true, work.block16, (short) 0);
            aes.setKey(work.block16, (short) 0);
            aes.decryptBlock(in, blockOff, out, outBlock);
            incCounter(counter, ctrOff, ctrNibbles);
        }

        short decLen = (short) (blocks * (short) 16);
        if (pad) {
            return AesHelper.isoUnpad(out, outOff, decLen);
        }
        return decLen;
    }

    public void deriveSdmSession(byte[] appKey, short keyOff, byte[] sv, short svOff, short svLen) {
        setKey(appKey, keyOff);
        computeMac(sv, svOff, svLen, sessMaster, (short) 0);
        generatePlaintexts(sessMaster, (short) 0);
        generateUpdatedKeys(sessMaster, (short) 0);
        generateSubkeys();
        updatedKeyIndex = 0;
    }

    private void computeMac(byte[] msg, short msgOff, short msgLen, byte[] mac, short macOff) {
        short blocks = (short) ((short) (msgLen + (short) 15) / (short) 16);
        boolean complete = (msgLen != 0) && ((short) (msgLen % (short) 16) == 0);

        if (blocks == 0) {
            blocks = 1;
            complete = false;
        }

        short lastBlockStart = (short) (msgOff + (short) ((short) (blocks - (short) 1) * (short) 16));
        short lastBlockLen = (short) (msgLen - (short) ((short) (blocks - (short) 1) * (short) 16));

        UtilCompat.arrayFillNonAtomic(padBlock, (short) 0, (short) 16, (byte) 0);
        if (complete) {
            UtilCompat.arrayCopy(msg, lastBlockStart, padBlock, (short) 0, (short) 16);
            AesHelper.xorBlock(padBlock, (short) 0, k1, (short) 0);
        } else {
            if (lastBlockLen > 0) {
                UtilCompat.arrayCopy(msg, lastBlockStart, padBlock, (short) 0, lastBlockLen);
            }
            padBlock[lastBlockLen] = (byte) 0x80;
            AesHelper.xorBlock(padBlock, (short) 0, k2, (short) 0);
        }

        UtilCompat.arrayFillNonAtomic(mac, macOff, (short) 16, (byte) 0);
        for (short i = 0; i < (short) (blocks - 1); i++) {
            short off = (short) (msgOff + (short) (i * (short) 16));
            for (short j = 0; j < 16; j++) {
                mac[(short) (macOff + j)] ^= msg[(short) (off + j)];
            }
            eval(mac, macOff, (short) 32, true, evalOut, (short) 0);
            UtilCompat.arrayCopy(evalOut, (short) 0, mac, macOff, (short) 16);
        }

        for (short j = 0; j < 16; j++) {
            mac[(short) (macOff + j)] ^= padBlock[j];
        }
        eval(mac, macOff, (short) 32, true, evalOut, (short) 0);
        UtilCompat.arrayCopy(evalOut, (short) 0, mac, macOff, (short) 16);
    }

    private void buildSessionVector(byte[] rndA, byte[] rndB, byte[] sv, short svOff) {
        sv[(short) (svOff + 0)] = 0x00;
        sv[(short) (svOff + 1)] = 0x01;
        sv[(short) (svOff + 2)] = 0x00;
        sv[(short) (svOff + 3)] = (byte) 0x80;
        sv[(short) (svOff + 4)] = rndA[0];
        sv[(short) (svOff + 5)] = rndA[1];
        sv[(short) (svOff + 6)] = (byte) (rndA[2] ^ rndB[0]);
        sv[(short) (svOff + 7)] = (byte) (rndA[3] ^ rndB[1]);
        sv[(short) (svOff + 8)] = (byte) (rndA[4] ^ rndB[2]);
        sv[(short) (svOff + 9)] = (byte) (rndA[5] ^ rndB[3]);
        sv[(short) (svOff + 10)] = (byte) (rndA[6] ^ rndB[4]);
        sv[(short) (svOff + 11)] = (byte) (rndA[7] ^ rndB[5]);
        UtilCompat.arrayCopy(rndB, (short) 6, sv, (short) (svOff + 12), (short) 10);
        UtilCompat.arrayCopy(rndA, (short) 8, sv, (short) (svOff + 22), (short) 8);
        sv[(short) (svOff + 30)] = (byte) 0x96;
        sv[(short) (svOff + 31)] = (byte) 0x69;
    }

    public void deriveAuthSession(byte[] appKey, short keyOff, byte[] rndA, byte[] rndB) {
        setKey(appKey, keyOff);
        buildSessionVector(rndA, rndB, work.sv32, (short) 0);
        computeMac(work.sv32, (short) 0, (short) 32, sessMaster, (short) 0);
        generatePlaintexts(sessMaster, (short) 0);
        generateUpdatedKeys(sessMaster, (short) 0);
        generateSubkeys();
        updatedKeyIndex = 0;
    }

    public void computeSessionMac(byte ukIndex, byte[] msg, short msgOff, short msgLen,
                                   byte[] mac, short macOff) {
        updatedKeyIndex = ukIndex;
        computeMac(msg, msgOff, msgLen, mac, macOff);
    }

    public void encryptAuthBlock(byte[] plain, short plainOff, short plainLen,
                                  byte[] out, short outOff) {
        UtilCompat.arrayFillNonAtomic(work.sessionKey, (short) 0, (short) 16, (byte) 0);
        updatedKeyIndex = 1;
        encryptLricb(work.sessionKey, (short) 0, Ntag424Constants.LRP_ENC_CTR_NIBBLES,
            false, plain, plainOff, plainLen, out, outOff);
    }

    private void generatePlaintexts(byte[] key, short keyOff) {
        UtilCompat.arrayCopy(key, keyOff, work.block16, (short) 0, (short) 16);
        for (short i = 0; i < PLAINTEXT_COUNT; i++) {
            aes.setKey(work.block16, (short) 0);
            aes.encryptBlock(CONST_55, (short) 0, work.block16, (short) 0);
            aes.setKey(work.block16, (short) 0);
            aes.encryptBlock(CONST_AA, (short) 0, plaintexts, (short) (i * (short) 16));
        }
    }

    private void generateUpdatedKeys(byte[] key, short keyOff) {
        aes.setKey(key, keyOff);
        aes.encryptBlock(CONST_AA, (short) 0, work.block16, (short) 0);
        for (short i = 0; i < UPDATED_KEY_COUNT; i++) {
            aes.setKey(work.block16, (short) 0);
            aes.encryptBlock(CONST_AA, (short) 0, updatedKeys, (short) (i * (short) 16));
            aes.encryptBlock(CONST_55, (short) 0, work.block16, (short) 0);
        }
    }

    private void generateSubkeys() {
        eval(ZERO, (short) 0, (short) 32, true, work.block16, (short) 0);
        mulPolyX(work.block16, k1);
        mulPolyX(k1, k2);
    }

    private static void mulPolyX(byte[] in, byte[] out) {
        boolean msb = (in[0] & (byte) 0x80) != 0;
        byte carry = 0;
        for (short i = 15; i >= 0; i--) {
            byte nextCarry = (byte) ((in[i] & (byte) 0x80) != 0 ? 1 : 0);
            out[i] = (byte) ((in[i] << 1) | carry);
            carry = nextCarry;
        }
        if (msb) {
            out[15] = (byte) (out[15] ^ (byte) 0x87);
        }
    }

    private static void incCounter(byte[] ctr, short ctrOff, short nibbles) {
        boolean carry = true;
        for (short i = (short) (nibbles - 1); i >= 0; i--) {
            byte nk;
            short byteIdx = (short) (ctrOff + (short) (i / (short) 2));
            if ((i & 1) != 0) {
                nk = (byte) (ctr[byteIdx] & 0x0F);
            } else {
                nk = (byte) ((ctr[byteIdx] >> 4) & 0x0F);
            }
            if (carry) {
                nk = (byte) (nk + 1);
            }
            carry = (nk > 0x0F);
            nk = (byte) (nk & 0x0F);
            if ((i & 1) != 0) {
                ctr[byteIdx] = (byte) ((ctr[byteIdx] & (byte) 0xF0) | nk);
            } else {
                ctr[byteIdx] = (byte) ((ctr[byteIdx] & (byte) 0x0F) | (byte) (nk << 4));
            }
            if (!carry) {
                break;
            }
        }
    }
}