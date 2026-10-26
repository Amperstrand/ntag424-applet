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

        // KNOWN DIVERGENCE (audit 2026-10-27): ReadData with length 0 returns
        // empty instead of the remaining file bytes; the quote below pins the
        // required silicon behavior (NT4H2421Gx 10.8.1).

        // NTA_SESSION: /// `length = 0` means "entire file from `offset`". Returns the
        // /// number of bytes copied into `buf`.

    void processReadData(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();
        if (lc < READ_HDR_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        byte fileNum = buffer[ISO7816.OFFSET_CDATA];
        FileSettings fs = host.getSettings(fileNum);
        if (fs == null) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        byte[] file = host.getFile(fileNum);
        if (file == null) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }

        byte comm = CommModeHelper.fileCommMode(fs, session, CommModeHelper.OP_READ);
        short hdrLen = host.unwrapHeaderMac(Ntag424Constants.CMD_READ_DATA, buffer,
            ISO7816.OFFSET_CDATA, READ_HDR_LEN, lc, comm);
        // NTA_TESTS: /// Replay a hardware-captured authenticated plain NDEF read through
        // /// `Session::read_file_plain` (AES session).
        // ///
        // /// This is the free-access edge case where the session remains authenticated
        // /// but the command still uses plain communication. The on-wire APDU is
        // /// identical to an unauthenticated plain read; the unique session-layer
        // /// behavior is advancing `CmdCtr` from 8 to 9 after success.

        // NTA_SESSION: /// counter, even when the wire framing is plain. MAC and Full modes also
        // /// derive or verify secure-messaging data from that counter; Plain mode

        if (!CommModeHelper.needsCommandMac(comm) && session.active) {
            // NT4H2421Gx §9.1.2: CmdCtr advances on EVERY command of an
            // authenticated session, including CommMode.Plain exchanges.
            // Verified against silicon via the ntag424 crate's HW-capture
            // replay test (plain read advances CmdCtr 9 -> 10).
            session.cmdCounter++;
        }
        if (hdrLen != READ_HDR_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short offset = UtilCompat.getOffset3(buffer, (short) (ISO7816.OFFSET_CDATA + 1));
        short length = UtilCompat.getOffset3(buffer, (short) (ISO7816.OFFSET_CDATA + 4));

        if (offset < 0 || length < 0 || (short) (offset + length) > fs.fileSize) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        if (!AccessControl.allowsRead(fs, session)) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if (fileNum == Ntag424Constants.FILE_NDEF && fs.sdmEnabled
                && !AccessControl.allowsSdmRead(fs)) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
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
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        byte[] file = host.getFile(fileNum);
        if (file == null) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }

        if (!AccessControl.allowsWrite(fs, session)) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
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
            // NTA_TESTS: /// Replay a hardware-captured authenticated plain NDEF read through
            // /// `Session::read_file_plain` (AES session).
            // ///
            // /// This is the free-access edge case where the session remains authenticated
            // /// but the command still uses plain communication. The on-wire APDU is
            // /// identical to an unauthenticated plain read; the unique session-layer
            // /// behavior is advancing `CmdCtr` from 8 to 9 after success.

            if (session.active) {
                // §9.1.2: CmdCtr advances on plain exchanges too (see
                // processReadData note; silicon-verified).
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
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
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
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }

        if (!AccessControl.allowsChange(fs, session)) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        short payloadOff = (short) (ISO7816.OFFSET_CDATA + 1);
        short payloadLen = (short) (lc - 1);

        if (payloadLen <= 8) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // NTA_CFS: /// The response is `MACt(8)` with SW `91 00`; no encrypted data is
        // /// returned. The response MAC is verified and `CmdCtr` is advanced on
        // /// success.

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
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        if (!AccessControl.allowsCounterRead(fs, session)) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
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
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        if (lc == 1) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        if (!session.active || session.authKeyNum != 0) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
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
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        if (!session.active || session.authKeyNum != 0) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        extraFiles.delete(fileNum);
        host.sendOkMacResponse(apdu);
    }
}
