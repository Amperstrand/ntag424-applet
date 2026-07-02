package com.ntag424;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

final class NxpDesfireHandler {
    private final byte[] scratch;
    private final NxpHandler host;

    NxpDesfireHandler(byte[] scratch, NxpHandler host) {
        this.scratch = scratch;
        this.host = host;
    }

    void processGetApplicationIds(APDU apdu) {
        apdu.setIncomingAndReceive();
        UtilCompat.arrayCopy(Ntag424Constants.APP_ID, (short) 0, scratch, (short) 0,
            Ntag424Constants.APP_ID_LEN);
        host.sendNxpResponse(apdu, scratch, (short) 0, Ntag424Constants.APP_ID_LEN,
            Ntag424Constants.SW_OK);
    }

    void processSelectApplication(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();
        byte hdrLc = buffer[ISO7816.OFFSET_LC];
        if (hdrLc != 0 && hdrLc != lc) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if (lc == Ntag424Constants.DF_NAME_LEN
                && UtilCompat.arrayEqual(buffer, ISO7816.OFFSET_CDATA,
                    Ntag424Constants.DF_NAME, (short) 0, Ntag424Constants.DF_NAME_LEN)) {
            host.sendNxpResponse(apdu, null, (short) 0, (short) 0, Ntag424Constants.SW_OK);
            return;
        }
        if (lc == Ntag424Constants.APP_ID_LEN
                && UtilCompat.arrayEqual(buffer, ISO7816.OFFSET_CDATA,
                    Ntag424Constants.APP_ID, (short) 0, Ntag424Constants.APP_ID_LEN)) {
            host.sendNxpResponse(apdu, null, (short) 0, (short) 0, Ntag424Constants.SW_OK);
            return;
        }
        ISOException.throwIt(
            (short) ((Ntag424Constants.SW_NXP_OK << 8) | (Ntag424Constants.SW_DESFIRE_APP_NOT_FOUND & 0xFF)));
    }
}
