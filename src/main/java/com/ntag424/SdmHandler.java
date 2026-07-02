package com.ntag424;

import javacard.framework.JCSystem;

// Secure Dynamic Messaging: inject UID, counter, encrypted data, and MAC on NDEF read.
public final class SdmHandler {
    private static final byte[] SV_MAC_PREFIX = {0x3C, (byte) 0xC3, 0x00, 0x01, 0x00, (byte) 0x80};
    private static final byte[] SV_ENC_PREFIX = {(byte) 0xC3, 0x3C, 0x00, 0x01, 0x00, (byte) 0x80};
    private static final byte[] HEX = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };

    private final AesHelper aes;
    private final AesCmac cmac;
    private final LrpPrimitive lrp;
    private final CryptoWork work;
    private boolean lrpSdmReady;

    public SdmHandler(AesHelper aes, AesCmac cmac, LrpPrimitive lrp, CryptoWork work) {
        this.aes = aes;
        this.cmac = cmac;
        this.lrp = lrp;
        this.work = work;
    }

    public void applyOnRead(byte[] uid, short uidOff, FileSettings fs,
                            byte[] file, short fileOff,
                            byte[] keyData, short keyOff, boolean lrpEnabled,
                            boolean bumpCounter, byte[] piccPad) {
        if (!fs.sdmEnabled) {
            return;
        }

        JCSystem.beginTransaction();
        if (bumpCounter) {
            fs.readCounter++;
        }
        lrpSdmReady = false;

        if (lrpEnabled && needsSdmSession(fs)) {
            deriveSdmKeyLrp(keyData, keyOff, uid, uidOff, fs);
            lrpSdmReady = true;
        }

        if (fs.sdmMetaReadPerm == Ntag424Constants.ACCESS_EVERYONE) {
            if (fs.sdmUid) {
                writeUidMirror(uid, uidOff, fs, file, fileOff);
            }
            if (fs.sdmReadCounter && fs.sdmCounterMirrored) {
                writeCounterMirror(fs, file, fileOff);
            }
        } else if (fs.sdmMetaReadPerm <= 4) {
            short metaKeyOff = (short) (fs.sdmMetaReadPerm * 16);
            encryptPiccData(uid, uidOff, fs, file, fileOff, keyData, metaKeyOff, piccPad);
        }

        if (fs.sdmEncryptFileData && fs.sdmFileReadPerm <= 4) {
            encryptFileRegion(uid, uidOff, fs, file, fileOff, keyData, keyOff, lrpEnabled);
        }

        if (fs.sdmFileReadPerm != Ntag424Constants.ACCESS_NONE) {
            computeSdmMac(fs, file, fileOff, uid, uidOff, keyData, keyOff, lrpEnabled);
        }
        JCSystem.commitTransaction();
    }

    private static boolean needsSdmSession(FileSettings fs) {
        return fs.sdmEncryptFileData
            || fs.sdmFileReadPerm != Ntag424Constants.ACCESS_NONE;
    }

    private void writeUidMirror(byte[] uid, short uidOff, FileSettings fs,
                                byte[] file, short fileOff) {
        short outOff = (short) (fileOff + fs.sdmUidOffset);
        if (fs.sdmUseAscii) {
            writeAsciiHex(uid, uidOff, Ntag424Constants.UID_LEN, file, outOff, (short) 14);
        } else {
            UtilCompat.arrayCopy(uid, uidOff, file, outOff, Ntag424Constants.UID_LEN);
        }
    }

    private void writeCounterMirror(FileSettings fs, byte[] file, short fileOff) {
        byte[] raw = work.block16;
        raw[0] = UtilCompat.getByteLSB(fs.readCounter, (byte) 0);
        raw[1] = UtilCompat.getByteLSB(fs.readCounter, (byte) 1);
        raw[2] = UtilCompat.getByteLSB(fs.readCounter, (byte) 2);
        short outOff = (short) (fileOff + fs.sdmReadCounterOffset);
        if (fs.sdmUseAscii) {
            writeAsciiHex(raw, (short) 0, (short) 3, file, outOff, (short) 6);
        } else {
            UtilCompat.arrayCopy(raw, (short) 0, file, outOff, (short) 3);
        }
    }

    private void writeAsciiHex(byte[] in, short inOff, short inLen,
                                 byte[] out, short outOff, short outLen) {
        for (short i = 0; i < inLen; i++) {
            byte b = in[(short) (inOff + i)];
            out[(short) (outOff + i * 2)] = HEX[(byte) ((b >> 4) & 0x0F)];
            out[(short) (outOff + i * 2 + 1)] = HEX[(byte) (b & 0x0F)];
        }
        if (outLen > (short) (inLen * 2)) {
            UtilCompat.arrayFillNonAtomic(out, (short) (outOff + inLen * 2),
                (short) (outLen - inLen * 2), (byte) 0);
        }
    }

    private void encryptPiccData(byte[] uid, short uidOff, FileSettings fs,
                                   byte[] file, short fileOff,
                                   byte[] keyData, short keyOff, byte[] piccPad) {
        byte[] plain = work.block16;
        byte tag = 0;
        short pos = 1;
        if (fs.sdmUid) {
            tag |= (byte) 0x80;
            tag |= (byte) (Ntag424Constants.UID_LEN & 0x0F);
            UtilCompat.arrayCopy(uid, uidOff, plain, pos, Ntag424Constants.UID_LEN);
            pos = (short) (pos + Ntag424Constants.UID_LEN);
        }
        if (fs.sdmReadCounter) {
            tag |= 0x40;
            UtilCompat.setOffset3(plain, pos, fs.readCounter);
            pos = (short) (pos + 3);
        }
        plain[0] = tag;
        if (pos < 16) {
            UtilCompat.arrayCopy(piccPad, (short) 0, plain, pos, (short) (16 - pos));
        }

        aes.setKey(keyData, keyOff);
        aes.encryptBlock(plain, (short) 0, work.sessionKey, (short) 0);
        // NT4H2421Gx: encrypted PICCData ciphertext is always ASCII on the contactless interface.
        writeAsciiHex(work.sessionKey, (short) 0, (short) 16, file,
            (short) (fileOff + fs.sdmPiccDataOffset), (short) 32);
    }

    private void encryptFileRegion(byte[] uid, short uidOff, FileSettings fs,
                                   byte[] file, short fileOff,
                                   byte[] keyData, short keyOff, boolean lrpEnabled) {
        if (lrpEnabled) {
            encryptFileRegionLrp(fs, file, fileOff);
            return;
        }

        deriveSdmKey(SV_ENC_PREFIX, (short) 0, (short) 6,
            keyData, keyOff, uid, uidOff, fs, true);
        aes.setKey(work.sessionKey, (short) 0);

        UtilCompat.setOffset3(work.block16, (short) 0, fs.readCounter);
        aes.encryptBlock(work.block16, (short) 0, work.sv32, (short) 0);

        short encBytes = (short) (fs.sdmEncLength / 2);
        short srcOff = (short) (fileOff + fs.sdmEncOffset);
        short dstOff = srcOff;

        for (short i = 0; i < encBytes; i += 16) {
            short chunk = (short) (encBytes - i);
            if (chunk > 16) chunk = 16;
            UtilCompat.arrayFillNonAtomic(work.block16, (short) 0, (short) 16, (byte) 0);
            UtilCompat.arrayCopy(file, (short) (srcOff + i), work.block16, (short) 0, chunk);
            cipherCbcEncrypt(aes, work.block16, (short) 0, (short) 16,
                work.sv32, work.macInput, (short) 0);
            UtilCompat.arrayCopy(work.macInput, (short) 0, file, (short) (dstOff + i), chunk);
            UtilCompat.arrayCopy(work.macInput, (short) 0, work.sv32, (short) 0, (short) 16);
        }

        if (fs.sdmUseAscii) {
            asciiInPlace(file, dstOff, encBytes);
        }
    }

    private void encryptFileRegionLrp(FileSettings fs, byte[] file, short fileOff) {
        UtilCompat.setOffset3(work.block16, (short) 0, fs.readCounter);
        UtilCompat.arrayFillNonAtomic(work.block16, (short) 3, (short) 3, (byte) 0);

        short encBytes = (short) (fs.sdmEncLength / 2);
        short srcOff = (short) (fileOff + fs.sdmEncOffset);
        short dstOff = srcOff;

        lrp.setUpdatedKeyIndex((byte) 1);
        for (short i = 0; i < encBytes; i += 16) {
            short chunk = (short) (encBytes - i);
            if (chunk > 16) chunk = 16;
            UtilCompat.arrayFillNonAtomic(work.macInput, (short) 0, (short) 16, (byte) 0);
            UtilCompat.arrayCopy(file, (short) (srcOff + i), work.macInput, (short) 0, chunk);
            lrp.encryptLricb(work.block16, (short) 0, Ntag424Constants.LRP_SDM_CTR_NIBBLES,
                false, work.macInput, (short) 0, (short) 16, work.macInput, (short) 0);
            UtilCompat.arrayCopy(work.macInput, (short) 0, file, (short) (dstOff + i), chunk);
        }

        if (fs.sdmUseAscii) {
            asciiInPlace(file, dstOff, encBytes);
        }
    }

    private void computeSdmMac(FileSettings fs, byte[] file, short fileOff,
                                byte[] uid, short uidOff, byte[] keyData, short keyOff,
                                boolean lrpEnabled) {
        short macInputOff = (short) (fileOff + fs.sdmMacInputOffset);
        short macInputEnd = (short) (fileOff + fs.sdmMacOffset);
        short macLen = (short) (macInputEnd - macInputOff);
        if (macLen < 0) {
            macLen = 0;
        }

        if (lrpEnabled) {
            if (!lrpSdmReady) {
                deriveSdmKeyLrp(keyData, keyOff, uid, uidOff, fs);
            }
            lrp.computeSessionMac((byte) 0, file, macInputOff, macLen, work.block16, (short) 0);
            AesCmac.shortenCmac(work.block16, (short) 0, work.sessionKey, (short) 0);
        } else {
            deriveSdmKey(SV_MAC_PREFIX, (short) 0, (short) 6,
                keyData, keyOff, uid, uidOff, fs, false);
            cmac.setKey(work.sessionKey, (short) 0);
            cmac.compute(file, macInputOff, macLen, work.block16, (short) 0);
            AesCmac.shortenCmac(work.block16, (short) 0, work.sessionKey, (short) 0);
        }

        short macOutOff = (short) (fileOff + fs.sdmMacOffset);
        if (fs.sdmUseAscii) {
            writeAsciiHex(work.sessionKey, (short) 0, (short) 8, file, macOutOff, (short) 16);
        } else {
            UtilCompat.arrayCopy(work.sessionKey, (short) 0, file, macOutOff, (short) 8);
        }
    }

    private void deriveSdmKeyLrp(byte[] keyData, short keyOff,
                                  byte[] uid, short uidOff, FileSettings fs) {
        byte[] sv = work.sv32;
        short pos = 0;
        sv[pos++] = 0x00;
        sv[pos++] = 0x01;
        sv[pos++] = 0x00;
        sv[pos++] = (byte) 0x80;

        boolean forceBoth = fs.sdmEncryptFileData;
        if (forceBoth || uidPresent(uid, uidOff)) {
            UtilCompat.arrayCopy(uid, uidOff, sv, pos, Ntag424Constants.UID_LEN);
            pos = (short) (pos + Ntag424Constants.UID_LEN);
        }
        if (forceBoth || fs.readCounter > 0) {
            UtilCompat.setOffset3(sv, pos, fs.readCounter);
            pos = (short) (pos + 3);
        }
        while (pos < 14) {
            sv[pos++] = 0;
        }
        sv[pos++] = 0x1E;
        sv[pos] = (byte) 0xE1;

        lrp.deriveSdmSession(keyData, keyOff, sv, (short) 0, (short) 16);
        lrpSdmReady = true;
    }

    private static boolean uidPresent(byte[] uid, short uidOff) {
        for (short i = 0; i < Ntag424Constants.UID_LEN; i++) {
            if (uid[(short) (uidOff + i)] != 0) {
                return true;
            }
        }
        return false;
    }

    private void deriveSdmKey(byte[] prefix, short prefixOff, short prefixLen,
                                  byte[] keyData, short keyOff,
                                  byte[] uid, short uidOff, FileSettings fs,
                                  boolean forEnc) {
        byte[] sv = work.sv32;
        UtilCompat.arrayCopy(prefix, prefixOff, sv, (short) 0, prefixLen);
        short pos = prefixLen;

        if (forEnc || uidPresent(uid, uidOff)) {
            UtilCompat.arrayCopy(uid, uidOff, sv, pos, Ntag424Constants.UID_LEN);
            pos = (short) (pos + Ntag424Constants.UID_LEN);
        }
        if (forEnc || fs.readCounter > 0) {
            UtilCompat.setOffset3(sv, pos, fs.readCounter);
        }

        // setKey() regenerates subkeys into work.sv32 — copy SV first.
        UtilCompat.arrayCopy(sv, (short) 0, work.block16, (short) 0, (short) 16);
        cmac.setKey(keyData, keyOff);
        cmac.compute(work.block16, (short) 0, (short) 16, work.sessionKey, (short) 0);
    }

    private void asciiInPlace(byte[] buf, short off, short len) {
        for (short i = (short) (len - 1); i >= 0; i--) {
            byte b = buf[(short) (off + i)];
            buf[(short) (off + i * 2)] = HEX[(byte) ((b >> 4) & 0x0F)];
            buf[(short) (off + i * 2 + 1)] = HEX[(byte) (b & 0x0F)];
        }
    }

    private void cipherCbcEncrypt(AesHelper helper, byte[] in, short inOff, short inLen,
                                   byte[] iv, byte[] out, short outOff) {
        short tmpIvOff = 16;
        UtilCompat.arrayCopy(iv, (short) 0, work.macInput, tmpIvOff, (short) 16);
        for (short i = 0; i < inLen; i++) {
            out[(short) (outOff + i)] = (byte) (in[(short) (inOff + i)] ^ work.macInput[(short) (tmpIvOff + i)]);
        }
        helper.encryptBlock(out, outOff, out, outOff);
    }
}
