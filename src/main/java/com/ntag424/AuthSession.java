package com.ntag424;

// EV2 auth session: session keys, command/response MAC, encrypted payloads.
import javacard.security.RandomData;

public final class AuthSession {
    private static final byte[] ENC_PURPOSE = {(byte) 0xA5, 0x5A};
    private static final byte[] MAC_PURPOSE = {0x5A, (byte) 0xA5};
    private static final byte[] ENC_IV_PREFIX = {(byte) 0xA5, 0x5A};
    private static final byte[] DEC_IV_PREFIX = {0x5A, (byte) 0xA5};

    public boolean active;
    public boolean sdmSuppress;
    public byte syncedAuthKey;
    public byte authKeyNum;
    public byte[] ti;
    public short cmdCounter;
    public byte[] rndA;
    public byte[] rndB;
    public byte authStage;
    public boolean authNonFirst;
    public boolean lrpMode;
    public final byte[] pcdCap2;
    public final byte[] encCtr;

    private final byte[] sessionEncKey;
    private final byte[] sessionMacKey;
    private final AesHelper aes;
    private final AesCmac cmac;
    private final LrpPrimitive lrp;
    private final RandomData rng;
    private final CryptoWork work;

    public AuthSession(AesHelper aes, AesCmac cmac, LrpPrimitive lrp, RandomData rng, CryptoWork work) {
        this.aes = aes;
        this.cmac = cmac;
        this.lrp = lrp;
        this.rng = rng;
        this.work = work;
        ti = new byte[4];
        rndA = new byte[16];
        rndB = new byte[16];
        pcdCap2 = new byte[Ntag424Constants.PCD_CAP2_LEN];
        encCtr = new byte[4];
        sessionEncKey = new byte[16];
        sessionMacKey = new byte[16];
    }

    public void reset() {
        active = false;
        clearType4Bridge();
        authStage = 0;
        authNonFirst = false;
        lrpMode = false;
        cmdCounter = 0;
        authKeyNum = 0;
        UtilCompat.arrayFillNonAtomic(ti, (short) 0, (short) 4, (byte) 0);
        UtilCompat.arrayFillNonAtomic(pcdCap2, (short) 0, Ntag424Constants.PCD_CAP2_LEN, (byte) 0);
        UtilCompat.arrayFillNonAtomic(encCtr, (short) 0, (short) 4, (byte) 0);
    }

    private void resetEncCtr() {
        UtilCompat.arrayFillNonAtomic(encCtr, (short) 0, (short) 4, (byte) 0);
    }

    public void beginAuth(byte keyNum, boolean nonFirst, boolean useLrp) {
        if (nonFirst) {
            authNonFirst = true;
            lrpMode = useLrp;
            resetEncCtr();
            UtilCompat.arrayFillNonAtomic(pcdCap2, (short) 0, Ntag424Constants.PCD_CAP2_LEN, (byte) 0);
            authKeyNum = keyNum;
            authStage = 1;
            rng.generateData(rndB, (short) 0, (short) 16);
            return;
        }
        reset();
        lrpMode = useLrp;
        authKeyNum = keyNum;
        authStage = 1;
        if (useLrp) {
            rng.generateData(ti, (short) 0, (short) 4);
        }
        rng.generateData(rndB, (short) 0, (short) 16);
    }

    public void storePcdCap2(byte[] buf, short off, byte lenCap) {
        short n = lenCap;
        if (n > Ntag424Constants.PCD_CAP2_LEN) {
            n = Ntag424Constants.PCD_CAP2_LEN;
        }
        if (n > 0) {
            UtilCompat.arrayCopy(buf, off, pcdCap2, (short) 0, n);
        }
    }

    public void deriveLrpSessionKeys(byte[] appKey, short keyOff) {
        lrp.deriveAuthSession(appKey, keyOff, rndA, rndB);
    }

    public boolean verifyLrpPcdResponse(byte[] pcdMac, short pcdMacOff) {
        byte[] input = work.macInput;
        UtilCompat.arrayCopy(rndA, (short) 0, input, (short) 0, (short) 16);
        UtilCompat.arrayCopy(rndB, (short) 0, input, (short) 16, (short) 16);
        lrp.computeSessionMac((byte) 0, input, (short) 0, (short) 32, work.block16, (short) 0);
        return UtilCompat.arrayEqual(work.block16, (short) 0, pcdMac, pcdMacOff, (short) 16);
    }

    public short buildLrpFirstResponse(PiccConfig cfg, byte[] out, short outOff) {
        byte[] plain = work.macInput;
        UtilCompat.arrayCopy(ti, (short) 0, plain, (short) 0, (short) 4);
        plain[4] = cfg.lrpEnabled ? PiccConfig.PDCAP21_LRP_BIT : (byte) 0;
        UtilCompat.arrayFillNonAtomic(plain, (short) 5, (short) 5, (byte) 0);
        UtilCompat.arrayCopy(pcdCap2, (short) 0, plain, (short) 10, Ntag424Constants.PCD_CAP2_LEN);
        lrp.encryptAuthBlock(plain, (short) 0, (short) 16, out, outOff);
        UtilCompat.arrayCopy(rndB, (short) 0, plain, (short) 0, (short) 16);
        UtilCompat.arrayCopy(rndA, (short) 0, plain, (short) 16, (short) 16);
        UtilCompat.arrayCopy(out, outOff, plain, (short) 32, (short) 16);
        lrp.computeSessionMac((byte) 0, plain, (short) 0, (short) 48,
            out, (short) (outOff + 16));
        encCtr[3] = 1;
        return (short) 32;
    }

    public short buildLrpNonFirstResponse(byte[] out, short outOff) {
        byte[] input = work.macInput;
        UtilCompat.arrayCopy(rndB, (short) 0, input, (short) 0, (short) 16);
        UtilCompat.arrayCopy(rndA, (short) 0, input, (short) 16, (short) 16);
        lrp.computeSessionMac((byte) 0, input, (short) 0, (short) 32, out, outOff);
        return (short) 16;
    }

    public void completeAuthLrp(boolean nonFirst) {
        if (!nonFirst) {
            cmdCounter = 0;
        }
        active = true;
        authStage = 0;
        bridgeType4();
    }

    public void completeAuth(byte[] appKey, short keyOff, boolean nonFirst) {
        aes.setKey(appKey, keyOff);
        deriveSessionKeys(appKey, keyOff);
        if (!nonFirst) {
            rng.generateData(ti, (short) 0, (short) 4);
            cmdCounter = 0;
        }
        active = true;
        authStage = 0;
        bridgeType4();
    }

    public void bridgeType4() {
        syncedAuthKey = authKeyNum;
        sdmSuppress = true;
    }

    public void clearType4Bridge() {
        syncedAuthKey = (byte) 0xFF;
        sdmSuppress = false;
    }

    public void deriveSessionKeys(byte[] appKey, short keyOff) {
        cmac.setKey(appKey, keyOff);
        fillSessionVector(ENC_PURPOSE);
        cmac.compute(work.sv32, (short) 0, (short) 32, sessionEncKey, (short) 0);
        fillSessionVector(MAC_PURPOSE);
        cmac.compute(work.sv32, (short) 0, (short) 32, sessionMacKey, (short) 0);
    }

    private void fillSessionVector(byte[] purpose) {
        byte[] sv = work.sv32;
        sv[0] = purpose[0];
        sv[1] = purpose[1];
        sv[2] = 0x00;
        sv[3] = 0x01;
        sv[4] = 0x00;
        sv[5] = (byte) 0x80;
        sv[6] = rndA[0];
        sv[7] = rndA[1];
        sv[8] = (byte) (rndA[2] ^ rndB[0]);
        sv[9] = (byte) (rndA[3] ^ rndB[1]);
        sv[10] = (byte) (rndA[4] ^ rndB[2]);
        sv[11] = (byte) (rndA[5] ^ rndB[3]);
        sv[12] = (byte) (rndA[6] ^ rndB[4]);
        sv[13] = (byte) (rndA[7] ^ rndB[5]);
        UtilCompat.arrayCopy(rndB, (short) 6, sv, (short) 14, (short) 10);
        UtilCompat.arrayCopy(rndA, (short) 8, sv, (short) 24, (short) 8);
    }

        // NTA_CHANNEL: /// Compute `MACt` over `Cmd || CmdCtr(LE) || TI || CmdHeader || CmdData`
        // /// (§9.1.9). Exposed for chained-command implementations

    public boolean verifyCommandMac(byte cmd, byte[] hdr, short hdrOff, short hdrLen,
                                     byte[] data, short dataOff, short dataLen,
                                     byte[] mac, short macOff) {
        byte[] input = work.macInput;
        short pos = 0;
        input[pos++] = cmd;
        input[pos++] = UtilCompat.getByteLSB(cmdCounter, (byte) 0);
        input[pos++] = UtilCompat.getByteLSB(cmdCounter, (byte) 1);
        UtilCompat.arrayCopy(ti, (short) 0, input, pos, (short) 4);
        pos = (short) (pos + 4);
        if (hdrLen > 0) {
            UtilCompat.arrayCopy(hdr, hdrOff, input, pos, hdrLen);
            pos = (short) (pos + hdrLen);
        }
        if (dataLen > 0) {
            UtilCompat.arrayCopy(data, dataOff, input, pos, dataLen);
            pos = (short) (pos + dataLen);
        }
        if (lrpMode) {
            return checkLrpMac(input, (short) 0, pos, mac, macOff);
        }
        return checkMac(input, (short) 0, pos, mac, macOff);
    }

    public void appendResponseMac(byte status2, byte[] data, short dataOff, short dataLen,
                                   byte[] out, short outOff) {
        byte[] input = work.macInput;
        short pos = 0;
        input[pos++] = status2;
        input[pos++] = UtilCompat.getByteLSB(cmdCounter, (byte) 0);
        input[pos++] = UtilCompat.getByteLSB(cmdCounter, (byte) 1);
        UtilCompat.arrayCopy(ti, (short) 0, input, pos, (short) 4);
        pos = (short) (pos + 4);
        if (dataLen > 0) {
            UtilCompat.arrayCopy(data, dataOff, input, pos, dataLen);
            pos = (short) (pos + dataLen);
        }
        if (lrpMode) {
            lrp.computeSessionMac((byte) 0, input, (short) 0, pos, work.block16, (short) 0);
            AesCmac.shortenCmac(work.block16, (short) 0, out, outOff);
            return;
        }
        cmac.setKey(sessionMacKey, (short) 0);
        cmac.compute(input, (short) 0, pos, work.block16, (short) 0);
        AesCmac.shortenCmac(work.block16, (short) 0, out, outOff);
    }

    public short decryptCommandData(byte[] in, short inOff, short inLen,
                                     byte[] out, short outOff) {
        if (lrpMode) {
            lrp.setUpdatedKeyIndex((byte) 1);
            return lrp.decryptLricb(encCtr, (short) 0, Ntag424Constants.LRP_ENC_CTR_NIBBLES,
                true, in, inOff, inLen, out, outOff);
        }
        aes.setKey(sessionEncKey, (short) 0);
        short decLen = aes.decryptSession(ENC_IV_PREFIX, (short) 0, ti, (short) 0,
            cmdCounter, in, inOff, inLen, out, outOff);
        return AesHelper.isoUnpad(out, outOff, decLen);
    }

    public short encryptResponseData(byte[] in, short inOff, short inLen,
                                      byte[] out, short outOff) {
        if (lrpMode) {
            lrp.setUpdatedKeyIndex((byte) 1);
            return lrp.encryptLricb(encCtr, (short) 0, Ntag424Constants.LRP_ENC_CTR_NIBBLES,
                true, in, inOff, inLen, out, outOff);
        }
        aes.setKey(sessionEncKey, (short) 0);
        return aes.encryptSession(DEC_IV_PREFIX, (short) 0, ti, (short) 0,
            cmdCounter, in, inOff, inLen, out, outOff);
    }

    private boolean checkLrpMac(byte[] input, short inOff, short inLen,
                                 byte[] mac, short macOff) {
        lrp.computeSessionMac((byte) 0, input, inOff, inLen, work.block16, (short) 0);
        AesCmac.shortenCmac(work.block16, (short) 0, work.sessionKey, (short) 0);
        return UtilCompat.arrayEqual(work.sessionKey, (short) 0, mac, macOff, (short) 8);
    }

    private boolean checkMac(byte[] input, short inOff, short inLen,
                              byte[] mac, short macOff) {
        cmac.setKey(sessionMacKey, (short) 0);
        cmac.compute(input, inOff, inLen, work.block16, (short) 0);
        AesCmac.shortenCmac(work.block16, (short) 0, work.sessionKey, (short) 0);
        return UtilCompat.arrayEqual(work.sessionKey, (short) 0, mac, macOff, (short) 8);
    }
}