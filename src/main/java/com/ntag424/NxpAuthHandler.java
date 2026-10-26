package com.ntag424;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

final class NxpAuthHandler {
    private final byte[] keys;
    private final byte[] keyVersions;
    private final byte[] scratch;
    private final PiccConfig piccConfig;
    private final AuthSession session;
    private final AesHelper aes;
    private final Type4Handler t4t;
    private final NxpHandler host;

    NxpAuthHandler(byte[] keys, byte[] keyVersions, byte[] scratch, PiccConfig piccConfig,
                   AuthSession session, AesHelper aes, Type4Handler t4t, NxpHandler host) {
        this.keys = keys;
        this.keyVersions = keyVersions;
        this.scratch = scratch;
        this.piccConfig = piccConfig;
        this.session = session;
        this.aes = aes;
        this.t4t = t4t;
        this.host = host;
    }

    void processAuthStage1(APDU apdu, boolean nonFirst) {
        byte[] buffer = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();
        short minLc = nonFirst ? (short) 1 : (short) 2;
        if (lc < minLc) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        byte keyNum = buffer[ISO7816.OFFSET_CDATA];
        if (keyNum >= Ntag424Constants.NUM_KEYS) {
            host.throwNxp((byte) 0xCA); // silicon: 91 CA for invalid key number
        }
        boolean origKey = Ntag424Constants.isOriginalityKey(keyNum);

        if (nonFirst) {
            if (session.authStage != 0) {
                host.throwNxp(Ntag424Constants.SW_NOT_ALLOWED);
            }
            if (!session.active) {
                if (!origKey || !piccConfig.lrpEnabled) {
                    host.throwNxp(Ntag424Constants.SW_NOT_ALLOWED);
                }
            }
        }

        byte gate = piccConfig.authGateSw2(origKey);
        if (gate != Ntag424Constants.SW_OK) {
            host.throwNxp(gate);
        }

        boolean useLrp = piccConfig.lrpEnabled;
        session.beginAuth(keyNum, nonFirst, useLrp);
        if (!nonFirst && useLrp && lc >= 2) {
            byte lenCap = buffer[(short) (ISO7816.OFFSET_CDATA + 1)];
            if (lc < (short) (2 + (short) (lenCap & (short) 0xFF))) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            if (lenCap > 0) {
                session.storePcdCap2(buffer, (short) (ISO7816.OFFSET_CDATA + 2), lenCap);
            }
        }

        if (useLrp) {
            scratch[0] = Ntag424Constants.AUTH_MODE_LRP;
            UtilCompat.arrayCopy(session.rndB, (short) 0, scratch, (short) 1, (short) 16);
            host.sendNxpResponse(apdu, scratch, (short) 0, (short) 17, Ntag424Constants.SW_ADDITIONAL_FRAME);
            return;
        }

        aes.setKey(keys, (short) (keyNum * 16));
        aes.encryptBlock(session.rndB, (short) 0, scratch, (short) 0);
        host.sendNxpResponse(apdu, scratch, (short) 0, (short) 16, Ntag424Constants.SW_ADDITIONAL_FRAME);
    }

    void processAuthStage2Lrp(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();
        if (lc != 32 || session.authStage != 1) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        UtilCompat.arrayCopy(buffer, ISO7816.OFFSET_CDATA, session.rndA, (short) 0, (short) 16);
        short keyOff = (short) (session.authKeyNum * 16);
        session.deriveLrpSessionKeys(keys, keyOff);

        boolean verified = session.verifyLrpPcdResponse(buffer, (short) (ISO7816.OFFSET_CDATA + 16));
        boolean origKey = Ntag424Constants.isOriginalityKey(session.authKeyNum);
        if (!verified) {
            session.clearType4Bridge();
            session.authStage = 0;
            piccConfig.onAuthFail(origKey);
            ISOException.throwIt(
                (short) ((Ntag424Constants.SW_NXP_OK << 8) | (Ntag424Constants.SW_AUTHENTICATION_ERROR & 0xFF)));
        }

        short respLen;
        if (origKey) {
            boolean wasNonFirst = session.authNonFirst;
            session.authStage = 0;
            session.authNonFirst = false;
            if (!wasNonFirst) {
                respLen = session.buildLrpFirstResponse(piccConfig, scratch, (short) 0);
            } else {
                respLen = session.buildLrpNonFirstResponse(scratch, (short) 0);
            }
        } else {
            session.completeAuthLrp(session.authNonFirst);
            t4t.invalidateSdmCache();
            if (!session.authNonFirst) {
                respLen = session.buildLrpFirstResponse(piccConfig, scratch, (short) 0);
            } else {
                respLen = session.buildLrpNonFirstResponse(scratch, (short) 0);
            }
        }
        piccConfig.onAuthSuccess(origKey);
        host.sendNxpResponse(apdu, scratch, (short) 0, respLen, Ntag424Constants.SW_OK);
    }

    void processAuthStage2Aes(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();
        if (lc != 32 || session.authStage != 1) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        aes.setKey(keys, (short) (session.authKeyNum * 16));
        aes.decryptCbc(buffer, ISO7816.OFFSET_CDATA, (short) 32, scratch, (short) 0);

        UtilCompat.arrayCopy(scratch, (short) 0, session.rndA, (short) 0, (short) 16);
        UtilCompat.arrayCopy(scratch, (short) 16, scratch, (short) 32, (short) 16);
        AesHelper.rotateRight(scratch, (short) 32, (short) 16);
        if (!UtilCompat.arrayEqual(scratch, (short) 32, session.rndB, (short) 0, (short) 16)) {
            session.clearType4Bridge();
            session.authStage = 0;
            boolean origKey = Ntag424Constants.isOriginalityKey(session.authKeyNum);
            piccConfig.onAuthFail(origKey);
            host.throwNxp(Ntag424Constants.SW_AUTHENTICATION_ERROR);
        }

        session.completeAuth(keys, (short) (session.authKeyNum * 16), session.authNonFirst);
        piccConfig.onAuthSuccess(Ntag424Constants.isOriginalityKey(session.authKeyNum));
        t4t.invalidateSdmCache();

        UtilCompat.arrayCopy(session.ti, (short) 0, scratch, (short) 0, (short) 4);
        UtilCompat.arrayCopy(session.rndA, (short) 0, scratch, (short) 48, (short) 16);
        AesHelper.rotateLeft(scratch, (short) 48, (short) 16);
        UtilCompat.arrayCopy(scratch, (short) 48, scratch, (short) 4, (short) 16);
        UtilCompat.arrayFillNonAtomic(scratch, (short) 20, (short) 12, (byte) 0);

        aes.encryptCbc(scratch, (short) 0, (short) 32, scratch, (short) 0);
        host.sendNxpResponse(apdu, scratch, (short) 0, (short) 32, Ntag424Constants.SW_OK);
    }

    void processChangeKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();
        if (!session.active || session.authKeyNum != 0) {
            host.throwNxp(Ntag424Constants.SW_NOT_ALLOWED);
        }

        byte keyNum = buffer[ISO7816.OFFSET_CDATA];
        if (keyNum >= Ntag424Constants.NUM_KEYS) {
            host.throwNxp((byte) 0xCA); // silicon: 91 CA for invalid key number
        }

        short payloadOff = (short) (ISO7816.OFFSET_CDATA + 1);
        short payloadLen = (short) (lc - 1);

        if (payloadLen <= 8) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short macOff = (short) (payloadOff + payloadLen - 8);
        host.verifyCommandMac(Ntag424Constants.CMD_CHANGE_KEY,
            buffer, ISO7816.OFFSET_CDATA, (short) 1,
            buffer, payloadOff, (short) (payloadLen - 8),
            macOff);
        payloadLen = (short) (payloadLen - 8);
        payloadLen = session.decryptCommandData(buffer, payloadOff, payloadLen, scratch, (short) 0);
        payloadOff = 0;
        session.cmdCounter++;

        short targetOff = (short) (keyNum * 16);
        if (keyNum == 0) {
            UtilCompat.arrayCopy(scratch, payloadOff, keys, targetOff, (short) 16);
            keyVersions[keyNum] = scratch[(short) (payloadOff + 16)];
            if (session.lrpMode) {
                session.deriveLrpSessionKeys(keys, targetOff);
            } else {
                session.deriveSessionKeys(keys, targetOff);
            }
        } else {
            for (short i = 0; i < 16; i++) {
                keys[(short) (targetOff + i)] ^= scratch[(short) (payloadOff + i)];
            }
            keyVersions[keyNum] = scratch[(short) (payloadOff + 16)];
        }

        // key 0 answers without MACt (5.16.2); K1-K4 with MACt (5.16.1)
        if (keyNum == 0) {
            host.sendNxpResponse(apdu, null, (short) 0, (short) 0, Ntag424Constants.SW_OK);
        } else {
            host.sendOkMacResponse(apdu);
        }
    }
}
