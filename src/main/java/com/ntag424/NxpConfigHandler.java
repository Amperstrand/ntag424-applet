package com.ntag424;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

final class NxpConfigHandler {
    private final byte[] uid;
    private final byte[] ridSalt;
    private final byte[] keyVersions;
    private final byte[] origSig;
    private final byte[] scratch;
    private final PiccConfig piccConfig;
    private final AuthSession session;
    private final Type4Handler t4t;
    private final NxpHandler host;
    private byte versionFrame;

    NxpConfigHandler(byte[] uid, byte[] ridSalt, byte[] keyVersions, byte[] origSig,
                     byte[] scratch, PiccConfig piccConfig, AuthSession session,
                     Type4Handler t4t, NxpHandler host) {
        this.uid = uid;
        this.ridSalt = ridSalt;
        this.keyVersions = keyVersions;
        this.origSig = origSig;
        this.scratch = scratch;
        this.piccConfig = piccConfig;
        this.session = session;
        this.t4t = t4t;
        this.host = host;
    }

    void reset() {
        versionFrame = 0;
    }

    boolean versionInProgress() {
        return versionFrame > 0;
    }

    void processGetVersion(APDU apdu) {
        short lc = apdu.setIncomingAndReceive();
        byte comm = CommModeHelper.metaCommMode(Ntag424Constants.CMD_GET_VERSION, session);
        host.unwrapHeaderMac(Ntag424Constants.CMD_GET_VERSION, apdu.getBuffer(),
            ISO7816.OFFSET_CDATA, (short) 0, lc, comm);
        versionFrame = 1;
        byte respComm = CommModeHelper.responseCommMode(Ntag424Constants.CMD_GET_VERSION,
            session, lc, (short) 0, null, CommModeHelper.OP_READ);
        host.sendProtectedResponse(apdu, respComm, Ntag424Constants.VERSION_HW, (short) 0,
            Ntag424Constants.VERSION_INFO_LEN, Ntag424Constants.SW_ADDITIONAL_FRAME);
    }

    void processGetVersionContinue(APDU apdu) {
        apdu.setIncomingAndReceive();
        byte respComm = CommModeHelper.metaCommMode(Ntag424Constants.CMD_GET_VERSION, session);
        if (versionFrame == 1) {
            versionFrame = 2;
            // intermediate frames are plain; MACt on final frame only (10.5.2)
            host.sendNxpResponse(apdu, Ntag424Constants.VERSION_SW, (short) 0,
                Ntag424Constants.VERSION_INFO_LEN, Ntag424Constants.SW_ADDITIONAL_FRAME);
            return;
        }
        if (versionFrame == 2) {
            versionFrame = 0;
            UtilCompat.arrayCopy(Ntag424Constants.VERSION_PRODUCTION, (short) 0, scratch, (short) 0,
                Ntag424Constants.PRODUCTION_INFO_LEN);
            UtilCompat.arrayCopy(uid, (short) 0, scratch,
                Ntag424Constants.VERSION_PRODUCTION_UID_OFFSET, Ntag424Constants.UID_LEN);
            host.sendProtectedResponse(apdu, respComm, scratch, (short) 0,
                Ntag424Constants.PRODUCTION_INFO_LEN, Ntag424Constants.SW_OK);
            return;
        }
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    void processGetCardUid(APDU apdu) {
        short lc = apdu.setIncomingAndReceive();
        if (!session.active) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        byte comm = CommModeHelper.metaCommMode(Ntag424Constants.CMD_GET_CARD_UID, session);
        host.unwrapHeaderMac(Ntag424Constants.CMD_GET_CARD_UID, apdu.getBuffer(),
            ISO7816.OFFSET_CDATA, (short) 0, lc, comm);
        UtilCompat.arrayCopy(uid, (short) 0, scratch, (short) 0, Ntag424Constants.UID_LEN);
        if (piccConfig.randomIdEnabled) {
            for (short i = 0; i < InstallParams.RID_SALT_LEN; i++) {
                scratch[i] = (byte) (scratch[i] ^ ridSalt[i]);
            }
        }
        byte respComm = CommModeHelper.responseCommMode(Ntag424Constants.CMD_GET_CARD_UID,
            session, lc, (short) 0, null, CommModeHelper.OP_READ);
        host.sendProtectedResponse(apdu, respComm, scratch, (short) 0, Ntag424Constants.UID_LEN);
    }

    void processReadSig(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();
        if (!session.active) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        byte comm = CommModeHelper.metaCommMode(Ntag424Constants.CMD_READ_SIG, session);
        short hdrLen = host.unwrapHeaderMac(Ntag424Constants.CMD_READ_SIG, buffer,
            ISO7816.OFFSET_CDATA, (short) 1, lc, comm);
        if (hdrLen != 1 || buffer[ISO7816.OFFSET_CDATA] != 0) {
            host.throwNxp(Ntag424Constants.SW_PARAMETER_ERROR);
        }
        byte respComm = CommModeHelper.responseCommMode(Ntag424Constants.CMD_READ_SIG,
            session, lc, (short) 1, null, CommModeHelper.OP_READ);
        host.sendProtectedResponse(apdu, respComm, origSig, (short) 0, Ntag424Constants.ORIG_SIG_LEN,
            Ntag424Constants.SW_READ_SIG_OK);
    }

    void processSetCardUid(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();
        if (!session.active || session.authKeyNum != 0) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if (lc != Ntag424Constants.UID_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        UtilCompat.arrayCopy(buffer, ISO7816.OFFSET_CDATA, uid, (short) 0, Ntag424Constants.UID_LEN);
        t4t.invalidateSdmCache();
        host.sendNxpResponse(apdu, null, (short) 0, (short) 0, Ntag424Constants.SW_OK);
    }

    void processGetKeyVersion(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();
        if (lc < 1) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        byte comm = CommModeHelper.metaCommMode(Ntag424Constants.CMD_GET_KEY_VERSION, session);
        short hdrLen = host.unwrapHeaderMac(Ntag424Constants.CMD_GET_KEY_VERSION, buffer,
            ISO7816.OFFSET_CDATA, (short) 1, lc, comm);
        if (hdrLen != 1) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        byte keyNum = buffer[ISO7816.OFFSET_CDATA];
        if (keyNum >= Ntag424Constants.NUM_KEYS) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        scratch[0] = keyVersions[keyNum];
        byte respComm = CommModeHelper.responseCommMode(Ntag424Constants.CMD_GET_KEY_VERSION,
            session, lc, (short) 1, null, CommModeHelper.OP_READ);
        host.sendProtectedResponse(apdu, respComm, scratch, (short) 0, (short) 1);
    }

    void processSetConfiguration(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();
        if (!session.active || session.authKeyNum != 0) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if (lc < 10) {
            host.throwNxp(Ntag424Constants.SW_LENGTH_ERROR);
        }

        byte option = buffer[ISO7816.OFFSET_CDATA];
        short encOff = (short) (ISO7816.OFFSET_CDATA + 1);
        short encLen = (short) (lc - 1 - 8);
        short macOff = (short) (encOff + encLen);

        host.verifyCommandMac(Ntag424Constants.CMD_SET_CONFIGURATION,
            buffer, ISO7816.OFFSET_CDATA, (short) 1,
            buffer, encOff, encLen,
            macOff);

        short decLen = session.decryptCommandData(buffer, encOff, encLen, scratch, (short) 0);
        session.cmdCounter++;

        if (option == PiccConfig.OPT_PICC) {
            if (decLen != PiccConfig.PICC_LEN) {
                host.throwNxp(Ntag424Constants.SW_LENGTH_ERROR);
            }
            if (!piccConfig.applyPicc(scratch[0])) {
                host.throwNxp(Ntag424Constants.SW_PARAMETER_ERROR);
            }
        } else if (option == PiccConfig.OPT_SM_CONFIG) {
            if (decLen != PiccConfig.SM_CONFIG_LEN) {
                host.throwNxp(Ntag424Constants.SW_LENGTH_ERROR);
            }
            if (!piccConfig.applySmConfig(scratch, (short) 0)) {
                host.throwNxp(Ntag424Constants.SW_PARAMETER_ERROR);
            }
        } else if (option == PiccConfig.OPT_CAPABILITY) {
            if (decLen != PiccConfig.CAPABILITY_LEN) {
                host.throwNxp(Ntag424Constants.SW_LENGTH_ERROR);
            }
            if (!piccConfig.applyCapability(scratch, (short) 0)) {
                host.throwNxp(Ntag424Constants.SW_PARAMETER_ERROR);
            }
        } else if (option == PiccConfig.OPT_FAIL_CTR) {
            if (decLen != PiccConfig.FAIL_CTR_LEN) {
                host.throwNxp(Ntag424Constants.SW_LENGTH_ERROR);
            }
            if (!piccConfig.applyFailCtr(scratch, (short) 0)) {
                host.throwNxp(Ntag424Constants.SW_PARAMETER_ERROR);
            }
        } else if (option == PiccConfig.OPT_HW) {
            if (decLen != PiccConfig.HW_LEN) {
                host.throwNxp(Ntag424Constants.SW_LENGTH_ERROR);
            }
            if (!piccConfig.applyHw(scratch[0])) {
                host.throwNxp(Ntag424Constants.SW_PARAMETER_ERROR);
            }
        } else {
            host.throwNxp(Ntag424Constants.SW_AUTHENTICATION_ERROR);
        }

        host.sendOkMacResponse(apdu);
    }
}
