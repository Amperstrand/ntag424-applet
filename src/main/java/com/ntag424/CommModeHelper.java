package com.ntag424;

// Resolve CommMode.Plain vs MAC/FULL per NTAG424 session + file/meta command rules.
public final class CommModeHelper {
    static final byte OP_READ = 0;
    static final byte OP_WRITE = 1;

    private CommModeHelper() {}

    static byte fileCommMode(FileSettings fs, AuthSession session, byte op) {
        if (!session.active) {
            return Ntag424Constants.COMM_PLAIN;
        }
        byte perm = op == OP_WRITE ? fs.writePerm : fs.readPerm;
        if (perm == Ntag424Constants.ACCESS_EVERYONE) {
            return Ntag424Constants.COMM_PLAIN;
        }
        return fs.commMode;
    }

    static byte metaCommMode(byte cmd, AuthSession session) {
        if (!session.active) {
            return Ntag424Constants.COMM_PLAIN;
        }
        if (cmd == Ntag424Constants.CMD_GET_FILE_SETTINGS
                || cmd == Ntag424Constants.CMD_GET_KEY_VERSION
                || cmd == Ntag424Constants.CMD_GET_VERSION) {
            return Ntag424Constants.COMM_MAC;
        }
        if (cmd == Ntag424Constants.CMD_GET_READ_COUNTER
                || cmd == Ntag424Constants.CMD_GET_CARD_UID
                || cmd == Ntag424Constants.CMD_READ_SIG) {
            return Ntag424Constants.COMM_FULL;
        }
        return Ntag424Constants.COMM_PLAIN;
    }

    static boolean needsCommandMac(byte commMode) {
        return commMode == Ntag424Constants.COMM_MAC
            || commMode == Ntag424Constants.COMM_FULL;
    }

    static byte responseCommMode(byte cmd, AuthSession session, short lc, short hdrLen,
                                  FileSettings fs, byte fileOp) {
        if (!session.active) {
            return Ntag424Constants.COMM_PLAIN;
        }
        if (lc == hdrLen || (hdrLen == 0 && lc == 0)) {
            return Ntag424Constants.COMM_PLAIN;
        }
        if (fs != null) {
            return fileCommMode(fs, session, fileOp);
        }
        return metaCommMode(cmd, session);
    }
}
