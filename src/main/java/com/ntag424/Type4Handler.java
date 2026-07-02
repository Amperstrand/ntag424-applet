package com.ntag424;

// ISO7816 Type 4 tag: SELECT / READ BINARY / UPDATE BINARY on CC, NDEF, and proprietary files.
import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;

public final class Type4Handler {
    private static final byte INS_SELECT = ISO7816.INS_SELECT;
    private static final byte INS_READ_BINARY = (byte) 0xB0;
    private static final byte INS_UPDATE_BINARY = (byte) 0xD6;

    private static final byte SELECT_P1_BY_FILEID = 0x00;
    private static final byte SELECT_P1_BY_EF_ID = 0x02;
    private static final byte SELECT_P1_BY_NAME = 0x04;
    private static final byte SELECT_P2_FIRST_OR_ONLY = (byte) 0x0C;
    private static final byte SELECT_P2_SELECT_EF = 0x00;

    private static final byte CC_TAG_NDEF_FILE_CONTROL = 0x04;
    private static final byte CC_LEN_NDEF_FILE_CONTROL = 6;
    private static final byte CC_TAG_PROP_FILE_CONTROL = 0x05;
    private static final byte CC_LEN_PROP_FILE_CONTROL = 6;
    private static final byte CC_PROP_READ_ACCESS = (byte) 0x82;
    private static final byte CC_PROP_WRITE_ACCESS = (byte) 0x83;
    private static final byte FILE_ACCESS_OPEN = 0x00;

    private byte selectedFileLow;
    private NxpHandler nxpHost;
    private final SdmSession sdmSession;
    private final byte[] ccFile;
    private final byte[] ndefFile;
    private final byte[] propFile;
    private final FileSettings ccSettings;
    private final FileSettings ndefSettings;
    private final FileSettings propSettings;
    private final AuthSession session;
    private final PiccConfig piccConfig;

    public Type4Handler(byte[] ccFile, byte[] ndefFile, byte[] propFile,
                        FileSettings ccSettings, FileSettings ndefSettings, FileSettings propSettings,
                        AuthSession session, SdmSession sdmSession, PiccConfig piccConfig) {
        this.ccFile = ccFile;
        this.ndefFile = ndefFile;
        this.propFile = propFile;
        this.ccSettings = ccSettings;
        this.ndefSettings = ndefSettings;
        this.propSettings = propSettings;
        this.session = session;
        this.sdmSession = sdmSession;
        this.piccConfig = piccConfig;
        setCurrentFile(Ntag424Constants.FID_CC);
    }

    void bindNxp(NxpHandler host) {
        nxpHost = host;
    }

    public void reset() {
        setCurrentFile(Ntag424Constants.FID_CC);
        sdmSession.invalidate();
    }

    public void invalidateSdmCache() {
        sdmSession.invalidate();
    }

    private short currentFile() {
        return (short) ((short) 0xE100 | (short) (selectedFileLow & 0xFF));
    }

    private void setCurrentFile(short fileId) {
        selectedFileLow = (byte) (fileId & 0xFF);
    }

    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];

        if (ins == INS_SELECT || ins == INS_UPDATE_BINARY) {
            sdmSession.invalidate();
        }

        if (ins == INS_SELECT) {
            processSelect(apdu);
        } else if (ins == INS_READ_BINARY) {
            processReadBinary(apdu);
        } else if (ins == INS_UPDATE_BINARY) {
            processUpdateBinary(apdu);
        } else {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void processSelect(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte p1 = buffer[ISO7816.OFFSET_P1];
        byte p2 = buffer[ISO7816.OFFSET_P2];

        if (!isSupportedSelectP2(p1, p2)) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        if (p1 == SELECT_P1_BY_FILEID || p1 == SELECT_P1_BY_EF_ID) {
            short fid = receiveSelectFid(apdu);
            selectByFid(fid);
            return;
        }

        short lc = apdu.setIncomingAndReceive();

        if (p1 == SELECT_P1_BY_NAME) {
            if (matchesNdefApplicationName(buffer, ISO7816.OFFSET_CDATA, lc)) {
                setCurrentFile(Ntag424Constants.FID_CC);
                return;
            }
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }

        ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
    }

    private short receiveSelectFid(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        buffer[ISO7816.OFFSET_LC] = 2;
        short total = apdu.setIncomingAndReceive();
        while (total < 2) {
            short more = apdu.receiveBytes((short) (ISO7816.OFFSET_CDATA + total));
            if (more <= 0) {
                break;
            }
            total = (short) (total + more);
        }
        if (total != 2) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short fid = UtilCompat.getShort(buffer, ISO7816.OFFSET_CDATA);
        if (!isKnownSelectFid(fid)) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        return fid;
    }

    private static boolean isKnownSelectFid(short fileId) {
        return fileId == Ntag424Constants.FID_DF
            || fileId == Ntag424Constants.FID_CC
            || fileId == Ntag424Constants.FID_NDEF
            || fileId == Ntag424Constants.FID_PROPRIETARY;
    }

    private boolean isSupportedSelectP2(byte p1, byte p2) {
        if (p1 != SELECT_P1_BY_FILEID && p1 != SELECT_P1_BY_EF_ID && p1 != SELECT_P1_BY_NAME) {
            return false;
        }
        return p2 == SELECT_P2_FIRST_OR_ONLY
            || p2 == SELECT_P2_SELECT_EF
            || p2 == 0x04
            || p2 == 0x08;
    }

    private void selectByFid(short fileId) {
        if (fileId == Ntag424Constants.FID_DF) {
            setCurrentFile(Ntag424Constants.FID_CC);
            return;
        }
        if (fileId == Ntag424Constants.FID_CC
            || fileId == Ntag424Constants.FID_NDEF
            || fileId == Ntag424Constants.FID_PROPRIETARY) {
            setCurrentFile(fileId);
            return;
        }
        ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
    }

    private byte[] ndefReadFile() {
        if (nxpHost == null) {
            return ndefFile;
        }
        return nxpHost.prepareSdmNdef(SdmSession.CH_ISO);
    }

    private short readBinaryOffset(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte p1 = buffer[ISO7816.OFFSET_P1];
        if ((p1 & (byte) 0x80) == 0) {
            return UtilCompat.getShort(buffer, ISO7816.OFFSET_P1);
        }
        short lc = apdu.setIncomingAndReceive();
        if (lc < 2) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        return UtilCompat.getShort(buffer, ISO7816.OFFSET_CDATA);
    }

    private void processReadBinary(APDU apdu) {
        short offset = readBinaryOffset(apdu);

        byte[] file;
        short fileLen;
        FileSettings fs;
        short sel = currentFile();

        if (sel == Ntag424Constants.FID_CC) {
            file = ccFile;
            fileLen = Ntag424Constants.CC_FILE_SIZE;
            fs = ccSettings;
        } else if (sel == Ntag424Constants.FID_NDEF) {
            fs = ndefSettings;
            fileLen = Ntag424Constants.NDEF_FILE_SIZE;
            if (ndefSettings.sdmEnabled && !session.sdmSuppress && !session.active) {
                file = ndefReadFile();
            } else {
                file = ndefFile;
            }
        } else if (sel == Ntag424Constants.FID_PROPRIETARY) {
            file = propFile;
            fileLen = Ntag424Constants.PROP_FILE_SIZE;
            fs = propSettings;
        } else {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }

        if (sel == Ntag424Constants.FID_PROPRIETARY) {
            if (!session.active || !AccessControl.allowsRead(propSettings, session.authKeyNum)) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
        } else if (!AccessControl.allowsRead(fs, session)) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if (offset < 0 || offset >= fileLen) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }

        short remain = (short) (fileLen - offset);
        short le = apdu.setOutgoing();
        if (le == 0 || le > remain) {
            le = remain;
        }
        if (le > Ntag424Constants.NDEF_READ_MAX) {
            le = Ntag424Constants.NDEF_READ_MAX;
        }

        short rfFrame = APDU.getOutBlockSize();
        if (le <= rfFrame) {
            byte[] buffer = apdu.getBuffer();
            UtilCompat.arrayCopy(file, offset, buffer, (short) 0, le);
            apdu.setOutgoingLength(le);
            apdu.sendBytes((short) 0, le);
        } else {
            apdu.setOutgoingLength(le);
            apdu.sendBytesLong(file, offset, le);
        }

        if (apdu.isCommandChainingCLA()) {
            sdmSession.beginIsoChain();
        } else {
            sdmSession.endIsoChain();
        }
    }

    private short receiveCommandData(APDU apdu, boolean allowChained) {
        byte[] buffer = apdu.getBuffer();
        short bytesLeft = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);
        short total = apdu.setIncomingAndReceive();
        if (total == 0) {
            return 0;
        }
        if (!allowChained && bytesLeft > total) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        short off = (short) (ISO7816.OFFSET_CDATA + total);
        while (bytesLeft > total) {
            short more = apdu.receiveBytes(off);
            if (more <= 0) {
                break;
            }
            total = (short) (total + more);
            off = (short) (off + more);
        }
        return total;
    }

    private void processUpdateBinary(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        FileSettings fs;
        byte[] file;
        short fileLen;
        short sel = currentFile();

        if (sel == Ntag424Constants.FID_NDEF) {
            fs = ndefSettings;
            file = ndefFile;
            fileLen = Ntag424Constants.NDEF_FILE_SIZE;
        } else if (sel == Ntag424Constants.FID_PROPRIETARY) {
            fs = propSettings;
            file = propFile;
            fileLen = Ntag424Constants.PROP_FILE_SIZE;
        } else {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            return;
        }

        if (!AccessControl.allowsWrite(fs, session.syncedAuthKey)) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        short offset = UtilCompat.getShort(buffer, ISO7816.OFFSET_P1);
        if (offset < 0 || offset >= fileLen) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }

        short lc = receiveCommandData(apdu, !piccConfig.disableChainedWrite);
        if (lc <= 0 || lc > Ntag424Constants.NDEF_READ_MAX) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short limit = (short) (offset + lc);
        if (limit > fileLen) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        JCSystem.beginTransaction();
        UtilCompat.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, file, offset, lc);
        JCSystem.commitTransaction();
        if (sel == Ntag424Constants.FID_NDEF) {
            sdmSession.invalidate();
        }
    }

    private static boolean matchesNdefApplicationName(byte[] data, short off, short lc) {
        if (lc < Ntag424Constants.DF_NAME_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if (!UtilCompat.arrayEqual(data, off, Ntag424Constants.DF_NAME,
                (short) 0, Ntag424Constants.DF_NAME_LEN)) {
            return false;
        }
        if (lc == Ntag424Constants.DF_NAME_LEN) {
            return true;
        }
        return lc == (short) (Ntag424Constants.DF_NAME_LEN + 1)
            && data[(short) (off + Ntag424Constants.DF_NAME_LEN)] == 0;
    }

    public static void buildCcFile(byte[] cc, short ndefSize) {
        short capsLen = 23;
        UtilCompat.setShort(cc, (short) 0, capsLen);
        cc[2] = Ntag424Constants.NDEF_MAPPING_VERSION;
        UtilCompat.setShort(cc, (short) 3, Ntag424Constants.NDEF_CC_MLE);
        UtilCompat.setShort(cc, (short) 5, Ntag424Constants.NDEF_CC_MLC);

        short pos = 7;
        cc[pos++] = CC_TAG_NDEF_FILE_CONTROL;
        cc[pos++] = CC_LEN_NDEF_FILE_CONTROL;
        UtilCompat.setShort(cc, pos, Ntag424Constants.FID_NDEF);
        pos = (short) (pos + 2);
        UtilCompat.setShort(cc, pos, ndefSize);
        pos = (short) (pos + 2);
        cc[pos++] = FILE_ACCESS_OPEN;
        cc[pos++] = FILE_ACCESS_OPEN;

        cc[pos++] = CC_TAG_PROP_FILE_CONTROL;
        cc[pos++] = CC_LEN_PROP_FILE_CONTROL;
        UtilCompat.setShort(cc, pos, Ntag424Constants.FID_PROPRIETARY);
        pos = (short) (pos + 2);
        UtilCompat.setShort(cc, pos, Ntag424Constants.PROP_FILE_SIZE);
        pos = (short) (pos + 2);
        cc[pos++] = CC_PROP_READ_ACCESS;
        cc[pos++] = CC_PROP_WRITE_ACCESS;

        UtilCompat.arrayFillNonAtomic(cc, capsLen, (short) (Ntag424Constants.CC_FILE_SIZE - capsLen), (byte) 0);
    }
}
