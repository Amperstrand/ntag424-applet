package com.ntag424;

// NXP commands used by NTAG424-SDM: auth, NDEF write, file settings, keys, counter helpers.
import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.RandomData;

public final class NxpHandler {
    private static final short MAC_LEN = 8;

    private final byte[] ccFile;
    private final byte[] ndefFile;
    private final byte[] propFile;
    private final FileSettings ccSettings;
    private final FileSettings ndefSettings;
    private final FileSettings propSettings;
    private final FileStore extraFiles;
    private final AuthSession session;
    private final byte[] scratch;
    private final Type4Handler t4t;
    private final SdmSession sdmSession;
    private final SdmHandler sdm;
    private final byte[] uid;
    private final byte[] keys;
    private final PiccConfig piccConfig;
    private final RandomData rng;

    private final NxpAuthHandler auth;
    private final NxpFileHandler files;
    private final NxpConfigHandler config;
    private final NxpDesfireHandler desfire;

    public NxpHandler(byte[] uid, byte[] ridSalt, byte[] keys, byte[] keyVersions,
                      byte[] ccFile, byte[] ndefFile, byte[] propFile, byte[] origSig,
                      FileSettings ccSettings, FileSettings ndefSettings, FileSettings propSettings,
                      FileStore extraFiles,
                      PiccConfig piccConfig,
                      AuthSession session,
                      AesHelper aes,
                      SdmHandler sdm, SdmSession sdmSession, Type4Handler t4t, byte[] scratch,
                      RandomData rng) {
        this.uid = uid;
        this.keys = keys;
        this.piccConfig = piccConfig;
        this.sdm = sdm;
        this.sdmSession = sdmSession;
        this.rng = rng;
        this.ccFile = ccFile;
        this.ndefFile = ndefFile;
        this.propFile = propFile;
        this.ccSettings = ccSettings;
        this.ndefSettings = ndefSettings;
        this.propSettings = propSettings;
        this.extraFiles = extraFiles;
        this.session = session;
        this.scratch = scratch;
        this.t4t = t4t;

        this.auth = new NxpAuthHandler(keys, keyVersions, scratch, piccConfig, session, aes, t4t, this);
        this.files = new NxpFileHandler(uid, keys, scratch, session, sdm, t4t, piccConfig, extraFiles, this);
        this.config = new NxpConfigHandler(uid, ridSalt, keyVersions, origSig, scratch, piccConfig, session, t4t, this);
        this.desfire = new NxpDesfireHandler(scratch, this);
    }

    public void reset() {
        session.reset();
        config.reset();
    }

    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];
        if (ins != Ntag424Constants.CMD_READ_DATA) {
            sdmSession.invalidate();
        }
        switch (ins) {
            case Ntag424Constants.CMD_AUTH_EV2_FIRST:
                auth.processAuthStage1(apdu, false);
                break;
            case Ntag424Constants.CMD_AUTH_EV2_NONFIRST:
                auth.processAuthStage1(apdu, true);
                break;
            case Ntag424Constants.CMD_ADDITIONAL_FRAME:
                if (session.authStage == 1) {
                    if (session.lrpMode) {
                        auth.processAuthStage2Lrp(apdu);
                    } else {
                        auth.processAuthStage2Aes(apdu);
                    }
                } else if (config.versionInProgress()) {
                    config.processGetVersionContinue(apdu);
                } else {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                }
                break;
            case Ntag424Constants.CMD_READ_DATA:
                files.processReadData(apdu);
                break;
            case Ntag424Constants.CMD_WRITE_DATA:
                files.processWriteData(apdu);
                break;
            case Ntag424Constants.CMD_GET_FILE_SETTINGS:
                files.processGetFileSettings(apdu);
                break;
            case Ntag424Constants.CMD_CHANGE_FILE_SETTINGS:
                files.processChangeFileSettings(apdu);
                break;
            case Ntag424Constants.CMD_SET_CONFIGURATION:
                config.processSetConfiguration(apdu);
                break;
            case Ntag424Constants.CMD_GET_KEY_VERSION:
                config.processGetKeyVersion(apdu);
                break;
            case Ntag424Constants.CMD_GET_READ_COUNTER:
                files.processGetReadCounter(apdu);
                break;
            case Ntag424Constants.CMD_CHANGE_KEY:
                auth.processChangeKey(apdu);
                break;
            case Ntag424Constants.CMD_SET_CARD_UID:
                config.processSetCardUid(apdu);
                break;
            case Ntag424Constants.CMD_GET_VERSION:
                config.processGetVersion(apdu);
                break;
            case Ntag424Constants.CMD_GET_CARD_UID:
                config.processGetCardUid(apdu);
                break;
            case Ntag424Constants.CMD_READ_SIG:
                config.processReadSig(apdu);
                break;
            case Ntag424Constants.CMD_GET_APPLICATION_IDS:
                desfire.processGetApplicationIds(apdu);
                break;
            case Ntag424Constants.CMD_SELECT_APPLICATION:
                desfire.processSelectApplication(apdu);
                break;
            case Ntag424Constants.CMD_CREATE_FILE:
                files.processCreateFile(apdu);
                break;
            case Ntag424Constants.CMD_DELETE_FILE:
                files.processDeleteFile(apdu);
                break;
            default:
                // silicon returns 91 7E for unknown NXP-session commands
                // (not ISO 6D00 — wire-verified 2026-10-27)
                throwNxp(Ntag424Constants.SW_LENGTH_ERROR);
        }
    }

    void throwNxp(byte sw2) {
        ISOException.throwIt((short) ((Ntag424Constants.SW_NXP_OK << 8) | (sw2 & 0xFF)));
    }

    // state-changing commands answer MACt(8) when a session is active;
    // sendNxpResponse throws, so the caller must advance CmdCtr first
    void sendOkMacResponse(APDU apdu) {
        if (session.active) {
            session.appendResponseMac(Ntag424Constants.SW_OK, null, (short) 0, (short) 0,
                scratch, (short) 0);
            sendNxpResponse(apdu, scratch, (short) 0, (short) 8, Ntag424Constants.SW_OK);
            return;
        }
        sendNxpResponse(apdu, null, (short) 0, (short) 0, Ntag424Constants.SW_OK);
    }

    short unwrapHeaderMac(byte cmd, byte[] buf, short hdrOff, short hdrLen,
                          short lc, byte comm) {
        if (!CommModeHelper.needsCommandMac(comm)) {
            if (lc < hdrLen) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            return hdrLen;
        }
        if (lc == hdrLen) {
            return hdrLen;
        }
        if (hdrLen == 0 && lc == 0) {
            return 0;
        }
        if (lc != (short) (hdrLen + MAC_LEN)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        verifyCommandMac(cmd, buf, hdrOff, hdrLen, buf, (short) 0, (short) 0,
            (short) (hdrOff + hdrLen));
        session.cmdCounter++;
        return hdrLen;
    }

    void verifyCommandMac(byte cmd, byte[] buf, short hdrOff, short hdrLen,
                          byte[] data, short dataOff, short dataLen, short macOff) {
        if (!session.verifyCommandMac(cmd, buf, hdrOff, hdrLen, data, dataOff, dataLen, buf, macOff)) {
            throwNxp(Ntag424Constants.SW_INTEGRITY_ERROR);
        }
    }

    void sendProtectedResponse(APDU apdu, byte commMode,
                               byte[] data, short dataOff, short dataLen) {
        sendProtectedResponse(apdu, commMode, data, dataOff, dataLen, Ntag424Constants.SW_OK);
    }

    void sendProtectedResponse(APDU apdu, byte commMode,
                               byte[] data, short dataOff, short dataLen, byte sw2) {
        if (commMode == Ntag424Constants.COMM_FULL && session.active) {
            short encLen = session.encryptResponseData(data, dataOff, dataLen, scratch, (short) 0);
            session.appendResponseMac(sw2, scratch, (short) 0, encLen, scratch, encLen);
            sendNxpResponse(apdu, scratch, (short) 0, (short) (encLen + 8), sw2);
            session.cmdCounter++;
            return;
        }
        if (commMode == Ntag424Constants.COMM_MAC && session.active) {
            if (dataLen > 0 && data != scratch) {
                UtilCompat.arrayCopy(data, dataOff, scratch, (short) 0, dataLen);
            }
            session.appendResponseMac(sw2, scratch, (short) 0, dataLen, scratch, dataLen);
            sendNxpResponse(apdu, scratch, (short) 0, (short) (dataLen + 8), sw2);
            session.cmdCounter++;
            return;
        }
        sendNxpResponse(apdu, data, dataOff, dataLen, sw2);
    }

    void sendNxpResponse(APDU apdu, byte[] data, short dataOff, short dataLen, byte sw2) {
        if (dataLen > 0) {
            apdu.setOutgoing();
            apdu.setOutgoingLength(dataLen);
            if (dataLen <= APDU.getOutBlockSize()) {
                byte[] buffer = apdu.getBuffer();
                UtilCompat.arrayCopy(data, dataOff, buffer, (short) 0, dataLen);
                apdu.sendBytes((short) 0, dataLen);
            } else {
                apdu.sendBytesLong(data, dataOff, dataLen);
            }
        }
        ISOException.throwIt((short) ((Ntag424Constants.SW_NXP_OK << 8) | (sw2 & 0xFF)));
    }

    FileSettings getSettings(byte fileNum) {
        if (fileNum == Ntag424Constants.FILE_CC) return ccSettings;
        if (fileNum == Ntag424Constants.FILE_NDEF) return ndefSettings;
        if (fileNum == Ntag424Constants.FILE_PROPRIETARY) return propSettings;
        return extraFiles.getSettings(fileNum);
    }

    byte[] getFile(byte fileNum) {
        if (fileNum == Ntag424Constants.FILE_CC) return ccFile;
        if (fileNum == Ntag424Constants.FILE_NDEF) return ndefFile;
        if (fileNum == Ntag424Constants.FILE_PROPRIETARY) return propFile;
        return extraFiles.getFile(fileNum);
    }

    void resetReadCounter(FileSettings fs) {
        fs.readCounter = 0;
        sdmSession.invalidate();
    }

    SdmSession sdmSession() {
        return sdmSession;
    }

    byte[] prepareSdmNdef(byte channel) {
        if (!ndefSettings.sdmEnabled || session.active || session.sdmSuppress) {
            return ndefFile;
        }
        if (!AccessControl.allowsSdmRead(ndefSettings)) {
            throwNxp(Ntag424Constants.SW_NOT_ALLOWED);
        }
        if (sdmSession.isPrepared(channel)) {
            return sdmSession.cache();
        }
        byte[] cache = sdmSession.cache();
        UtilCompat.arrayCopyNonAtomic(ndefFile, (short) 0, cache, (short) 0, ndefSettings.fileSize);
        byte keyNum = ndefSettings.sdmFileReadPerm;
        if (keyNum <= 4) {
            sdmSession.freshPiccPad(rng);
            sdm.applyOnRead(uid, (short) 0, ndefSettings, cache, (short) 0,
                keys, (short) (keyNum * 16), piccConfig.lrpEnabled, true, sdmSession.piccPad());
        }
        sdmSession.markPrepared(channel);
        return cache;
    }
}
