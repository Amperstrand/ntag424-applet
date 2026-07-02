package com.ntag424;

// NTAG424 access rights: 0-4 = key, 0x0E = free, 0x0F = deny.
public final class AccessControl {
    private AccessControl() {}

    public static boolean allowsRead(FileSettings fs, AuthSession session) {
        return allowsKeyPerm(fs.readPerm, fs.readWritePerm, session);
    }

    public static boolean allowsRead(FileSettings fs, byte authKeyNum) {
        return allowsKeyPerm(fs.readPerm, fs.readWritePerm, authKeyNum);
    }

    public static boolean allowsWrite(FileSettings fs, AuthSession session) {
        return allowsKeyPerm(fs.writePerm, fs.readWritePerm, session);
    }

    public static boolean allowsWrite(FileSettings fs, byte authKeyNum) {
        return allowsKeyPerm(fs.writePerm, fs.readWritePerm, authKeyNum);
    }

    public static boolean allowsChange(FileSettings fs, AuthSession session) {
        return allowsKeyPerm(fs.changePerm, (byte) 0x0F, session);
    }

    public static boolean allowsCounterRead(FileSettings fs, AuthSession session) {
        if (!fs.sdmEnabled) {
            return allowsRead(fs, session);
        }
        if (fs.sdmReadCounterRetrievalPerm == Ntag424Constants.ACCESS_NONE
                || fs.sdmReadCounterRetrievalPerm == Ntag424Constants.ACCESS_EVERYONE) {
            return allowsRead(fs, session);
        }
        return allowsKeyPerm(fs.sdmReadCounterRetrievalPerm, fs.readWritePerm, session);
    }

    public static boolean allowsSdmRead(FileSettings fs) {
        if (!fs.sdmEnabled || !fs.sdmReadCounterLimit) {
            return true;
        }
        return fs.readCounter < fs.sdmMaxReadCounter;
    }

    private static boolean allowsKeyPerm(byte perm, byte altPerm, AuthSession session) {
        if (perm == Ntag424Constants.ACCESS_NONE) {
            return false;
        }
        if (perm == Ntag424Constants.ACCESS_EVERYONE) {
            return true;
        }
        if (!session.active) {
            return false;
        }
        return allowsKeyPerm(perm, altPerm, session.authKeyNum);
    }

    private static boolean allowsKeyPerm(byte perm, byte altPerm, byte authKeyNum) {
        if (perm == Ntag424Constants.ACCESS_NONE) {
            return false;
        }
        if (perm == Ntag424Constants.ACCESS_EVERYONE) {
            return true;
        }
        if (authKeyNum > 4) {
            return false;
        }
        if (perm <= 4 && authKeyNum == perm) {
            return true;
        }
        if (altPerm != Ntag424Constants.ACCESS_NONE
                && altPerm != Ntag424Constants.ACCESS_EVERYONE
                && altPerm <= 4
                && authKeyNum == altPerm) {
            return true;
        }
        return false;
    }
}
