package com.ntag424;

// Install-time params from gp install --params: UID (7 B) + optional Read_Sig blob (56 B).
public final class InstallParams {

    private static final byte ORIG_SIG_OFF = 7;
    private static final byte INSTALL_LEN_ORIG_SIG = 63;
    public static final byte RID_SALT_LEN = 4;

    private InstallParams() {}

    public static void load(byte[] uid, short uidOff, byte[] origSig, short sigOff,
                            byte[] install, short installOff, byte installLen) {
        UtilCompat.arrayFillNonAtomic(uid, uidOff, Ntag424Constants.UID_LEN, (byte) 0);

        if (install != null && installLen >= Ntag424Constants.UID_LEN) {
            UtilCompat.arrayCopy(install, installOff, uid, uidOff, Ntag424Constants.UID_LEN);
        }

        if (install != null && installLen >= INSTALL_LEN_ORIG_SIG) {
            UtilCompat.arrayCopy(install, (short) (installOff + ORIG_SIG_OFF), origSig, sigOff,
                Ntag424Constants.ORIG_SIG_LEN);
        } else {
            UtilCompat.arrayCopy(Ntag424Constants.DEFAULT_ORIG_SIG, (short) 0, origSig, sigOff,
                Ntag424Constants.ORIG_SIG_LEN);
        }
    }

    // ponytail: 4-byte RID salt from UID when install params omit explicit salt
    public static void deriveRidSalt(byte[] uid, short uidOff, byte[] salt, short saltOff) {
        for (short i = 0; i < RID_SALT_LEN; i++) {
            salt[(short) (saltOff + i)] = (byte) (uid[(short) (uidOff + i)]
                ^ uid[(short) (uidOff + i + 3)]);
        }
    }
}
