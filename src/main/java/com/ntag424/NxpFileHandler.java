package com.ntag424;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;

final class NxpFileHandler {
    private static final short READ_HDR_LEN = 7;
    private static final short MAC_LEN = 8;

    private final byte[] uid;
    private final byte[] keys;
    private final byte[] scratch;
    private final AuthSession session;
    private final SdmHandler sdm;
    private final Type4Handler t4t;
    private final PiccConfig piccConfig;
    private final FileStore extraFiles;
    private final NxpHandler host;

    NxpFileHandler(byte[] uid, byte[] keys, byte[] scratch, AuthSession session,
                   SdmHandler sdm, Type4Handler t4t, PiccConfig piccConfig,
                   FileStore extraFiles, NxpHandler host) {
        this.uid = uid;
        this.keys = keys;
        this.scratch = scratch;
        this.session = session;
        this.sdm = sdm;
        this.t4t = t4t;
        this.piccConfig = piccConfig;
        this.extraFiles = extraFiles;
        this.host = host;
    }

    void processReadData(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();
        if (lc < READ_HDR_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        byte fileNum = buffer[ISO7816.OFFSET_CDATA];
        FileSettings fs = host.getSettings(fileNum);
        if (fs == null) {
            host.throwNxp(Ntag424Constants.SW_FILE_NOT_FOUND);
        }
        byte[] file = host.getFile(fileNum);
        if (file == null) {
            host.throwNxp(Ntag424Constants.SW_FILE_NOT_FOUND);
        }

        byte comm = CommModeHelper.fileCommMode(fs, session, CommModeHelper.OP_READ);
        short hdrLen = host.unwrapHeaderMac(Ntag424Constants.CMD_READ_DATA, buffer,
            ISO7816.OFFSET_CDATA, READ_HDR_LEN, lc, comm);
        if (!CommModeHelper.needsCommandMac(comm) && session.active) {
            // CmdCtr advances on plain commands too (9.1.2)
            session.cmdCounter++;
        }
        if (hdrLen != READ_HDR_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short offset = UtilCompat.getOffset3(buffer, (short) (ISO7816.OFFSET_CDATA + 1));
        short length = UtilCompat.getOffset3(buffer, (short) (ISO7816.OFFSET_CDATA + 4));
        if (length == 0) {
            // NT4H2421Gx 10.8.1: length=0 means "entire file from offset",
            // capped at the short-Le response limit
            length = (short) (fs.fileSize - offset);
            if (length > 256) {
                length = 256;
            }
        }

        if (offset < 0 || length < 0 || (short) (offset + length) > fs.fileSize) {
            // silicon returns 91 BE (boundary), not ISO wrong-length
            host.throwNxp(Ntag424Constants.SW_BOUNDARY_ERROR);
        }

        if (!AccessControl.allowsRead(fs, session)) {
            host.throwNxp(Ntag424Constants.SW_NOT_ALLOWED);
        }
        if (fileNum == Ntag424Constants.FILE_NDEF && fs.sdmEnabled
                && !AccessControl.allowsSdmRead(fs)) {
            host.throwNxp(Ntag424Constants.SW_NOT_ALLOWED);
        }

        byte[] outFile = file;
        if (fileNum == Ntag424Constants.FILE_NDEF && fs.sdmEnabled
                && !session.active && comm == Ntag424Constants.COMM_PLAIN) {
            outFile = host.prepareSdmNdef(SdmSession.CH_NATIVE);
        }

        UtilCompat.arrayCopy(outFile, offset, scratch, (short) 0, length);
        byte respComm = CommModeHelper.responseCommMode(Ntag424Constants.CMD_READ_DATA,
            session, lc, READ_HDR_LEN, fs, CommModeHelper.OP_READ);
        host.sendProtectedResponse(apdu, respComm, scratch, (short) 0, length);
    }

    void processWriteData(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();
        if (lc < READ_HDR_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        byte fileNum = buffer[ISO7816.OFFSET_CDATA];
        FileSettings fs = host.getSettings(fileNum);
        if (fs == null) {
            host.throwNxp(Ntag424Constants.SW_FILE_NOT_FOUND);
        }
        byte[] file = host.getFile(fileNum);
        if (file == null) {
            host.throwNxp(Ntag424Constants.SW_FILE_NOT_FOUND);
        }

        if (!AccessControl.allowsWrite(fs, session)) {
            host.throwNxp(Ntag424Constants.SW_NOT_ALLOWED);
        }

        byte comm = CommModeHelper.fileCommMode(fs, session, CommModeHelper.OP_WRITE);
        short offset = UtilCompat.getOffset3(buffer, (short) (ISO7816.OFFSET_CDATA + 1));
        short length = UtilCompat.getOffset3(buffer, (short) (ISO7816.OFFSET_CDATA + 4));
        short dataOff;
        short dataLen;

        if (comm == Ntag424Constants.COMM_PLAIN) {
            if (lc < (short) (READ_HDR_LEN + length)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            dataOff = (short) (ISO7816.OFFSET_CDATA + READ_HDR_LEN);
            dataLen = (short) (lc - READ_HDR_LEN);
            if (session.active) {
                session.cmdCounter++;
            }
        } else if (comm == Ntag424Constants.COMM_MAC) {
            if (lc != (short) (READ_HDR_LEN + length + MAC_LEN)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            dataOff = (short) (ISO7816.OFFSET_CDATA + READ_HDR_LEN);
            dataLen = length;
            host.verifyCommandMac(Ntag424Constants.CMD_WRITE_DATA, buffer, ISO7816.OFFSET_CDATA,
                READ_HDR_LEN, buffer, dataOff, dataLen,
                (short) (dataOff + dataLen));
            session.cmdCounter++;
        } else {
            if (lc < (short) (READ_HDR_LEN + MAC_LEN)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            short macOff = (short) (ISO7816.OFFSET_CDATA + lc - MAC_LEN);
            short encOff = (short) (ISO7816.OFFSET_CDATA + READ_HDR_LEN);
            short encLen = (short) (macOff - encOff);
            host.verifyCommandMac(Ntag424Constants.CMD_WRITE_DATA, buffer, ISO7816.OFFSET_CDATA,
                READ_HDR_LEN, buffer, encOff, encLen, macOff);
            dataLen = session.decryptCommandData(buffer, encOff, encLen, scratch, (short) 0);
            session.cmdCounter++;
            dataOff = 0;
            if (dataLen != length) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
        }

        if (offset < 0 || dataLen != length || (short) (offset + length) > fs.fileSize) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        JCSystem.beginTransaction();
        if (comm == Ntag424Constants.COMM_FULL) {
            UtilCompat.arrayCopy(scratch, (short) 0, file, offset, dataLen);
        } else {
            UtilCompat.arrayCopy(buffer, dataOff, file, offset, dataLen);
        }
        JCSystem.commitTransaction();
        if (fileNum == Ntag424Constants.FILE_NDEF) {
            t4t.invalidateSdmCache();
        }
        byte respComm = CommModeHelper.responseCommMode(Ntag424Constants.CMD_WRITE_DATA,
            session, lc, READ_HDR_LEN, fs, CommModeHelper.OP_WRITE);
        host.sendProtectedResponse(apdu, respComm, null, (short) 0, (short) 0);
    }

    void processGetFileSettings(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();
        if (lc < 1) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        byte comm = CommModeHelper.metaCommMode(Ntag424Constants.CMD_GET_FILE_SETTINGS, session);
        short hdrLen = host.unwrapHeaderMac(Ntag424Constants.CMD_GET_FILE_SETTINGS, buffer,
            ISO7816.OFFSET_CDATA, (short) 1, lc, comm);
        if (hdrLen != 1) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        byte fileNum = buffer[ISO7816.OFFSET_CDATA];
        FileSettings fs = host.getSettings(fileNum);
        if (fs == null) {
            host.throwNxp(Ntag424Constants.SW_FILE_NOT_FOUND);
        }

        short len = fs.encodeFull(Ntag424Constants.FILE_TYPE_STD, scratch, (short) 0);
        byte respComm = CommModeHelper.responseCommMode(Ntag424Constants.CMD_GET_FILE_SETTINGS,
            session, lc, (short) 1, null, CommModeHelper.OP_READ);
        host.sendProtectedResponse(apdu, respComm, scratch, (short) 0, len);
    }

    void processChangeFileSettings(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();
        if (lc < 2) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        byte fileNum = buffer[ISO7816.OFFSET_CDATA];
        FileSettings fs = host.getSettings(fileNum);
        if (fs == null) {
            host.throwNxp(Ntag424Constants.SW_FILE_NOT_FOUND);
        }

        if (!AccessControl.allowsChange(fs, session)) {
            host.throwNxp(Ntag424Constants.SW_NOT_ALLOWED);
        }

        short payloadOff = (short) (ISO7816.OFFSET_CDATA + 1);
        short payloadLen = (short) (lc - 1);

        if (payloadLen <= 8) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short macOff = (short) (payloadOff + payloadLen - 8);
        host.verifyCommandMac(Ntag424Constants.CMD_CHANGE_FILE_SETTINGS,
            buffer, ISO7816.OFFSET_CDATA, (short) 1,
            buffer, payloadOff, (short) (payloadLen - 8),
            macOff);
        payloadLen = (short) (payloadLen - 8);
        short decLen = session.decryptCommandData(buffer, payloadOff,
            payloadLen, scratch, (short) 1);
        scratch[0] = Ntag424Constants.FILE_TYPE_STD;
        session.cmdCounter++;

        boolean wasSdm = fs.sdmEnabled;
        fs.decodeMutable(scratch, (short) 0, (short) (decLen + 1));
        if (fs.sdmEnabled && !wasSdm) {
            host.resetReadCounter(fs);
        } else {
            host.sdmSession().invalidate();
        }

        host.sendOkMacResponse(apdu);
    }

    void processGetReadCounter(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();
        if (lc < 1) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        byte comm = CommModeHelper.metaCommMode(Ntag424Constants.CMD_GET_READ_COUNTER, session);
        short hdrLen = host.unwrapHeaderMac(Ntag424Constants.CMD_GET_READ_COUNTER, buffer,
            ISO7816.OFFSET_CDATA, (short) 1, lc, comm);
        if (hdrLen != 1) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        byte fileNum = buffer[ISO7816.OFFSET_CDATA];
        FileSettings fs = host.getSettings(fileNum);
        if (fs == null) {
            host.throwNxp(Ntag424Constants.SW_FILE_NOT_FOUND);
        }
        if (!AccessControl.allowsCounterRead(fs, session)) {
            host.throwNxp(Ntag424Constants.SW_NOT_ALLOWED);
        }
        UtilCompat.setOffset3(scratch, (short) 0, fs.readCounter);
        byte respComm = CommModeHelper.responseCommMode(Ntag424Constants.CMD_GET_READ_COUNTER,
            session, lc, (short) 1, null, CommModeHelper.OP_READ);
        host.sendProtectedResponse(apdu, respComm, scratch, (short) 0, (short) 3);
    }

    void processCreateFile(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();
        if (lc < 1) {
            host.throwNxp(Ntag424Constants.SW_LENGTH_ERROR);
        }
        byte fileNum = buffer[ISO7816.OFFSET_CDATA];
        if (fileNum == Ntag424Constants.FILE_CC
                || fileNum == Ntag424Constants.FILE_NDEF
                || fileNum == Ntag424Constants.FILE_PROPRIETARY) {
            host.throwNxp(Ntag424Constants.SW_FILE_EXISTS);
        }
        if (extraFiles.isAllocated(fileNum)) {
            host.throwNxp(Ntag424Constants.SW_FILE_EXISTS);
        }
        if (extraFiles.slotIndex(fileNum) < 0) {
            host.throwNxp(Ntag424Constants.SW_FILE_NOT_FOUND);
        }
        if (lc == 1) {
            host.throwNxp(Ntag424Constants.SW_FILE_NOT_FOUND);
        }
        if (!session.active || session.authKeyNum != 0) {
            host.throwNxp(Ntag424Constants.SW_NOT_ALLOWED);
        }

        short payloadOff = (short) (ISO7816.OFFSET_CDATA + 1);
        short payloadLen = (short) (lc - 1);
        if (payloadLen <= 8) {
            host.throwNxp(Ntag424Constants.SW_LENGTH_ERROR);
        }
        short macOff = (short) (payloadOff + payloadLen - 8);
        host.verifyCommandMac(Ntag424Constants.CMD_CREATE_FILE,
            buffer, ISO7816.OFFSET_CDATA, (short) 1,
            buffer, payloadOff, (short) (payloadLen - 8),
            macOff);
        payloadLen = (short) (payloadLen - 8);
        short decLen = session.decryptCommandData(buffer, payloadOff,
            payloadLen, scratch, (short) 0);
        session.cmdCounter++;

        if (!extraFiles.create(fileNum, scratch, (short) 0, decLen)) {
            host.throwNxp(Ntag424Constants.SW_PARAMETER_ERROR);
        }
        host.sendOkMacResponse(apdu);
    }

    void processDeleteFile(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();
        if (lc != 1) {
            host.throwNxp(Ntag424Constants.SW_LENGTH_ERROR);
        }
        byte fileNum = buffer[ISO7816.OFFSET_CDATA];
        if (fileNum == Ntag424Constants.FILE_CC
                || fileNum == Ntag424Constants.FILE_NDEF
                || fileNum == Ntag424Constants.FILE_PROPRIETARY) {
            host.throwNxp(Ntag424Constants.SW_PARAMETER_ERROR);
        }
        if (!extraFiles.isAllocated(fileNum)) {
            host.throwNxp(Ntag424Constants.SW_FILE_NOT_FOUND);
        }
        if (!session.active || session.authKeyNum != 0) {
            host.throwNxp(Ntag424Constants.SW_NOT_ALLOWED);
        }
        extraFiles.delete(fileNum);
        host.sendOkMacResponse(apdu);
    }
}
