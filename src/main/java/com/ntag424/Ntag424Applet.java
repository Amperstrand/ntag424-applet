package com.ntag424;

// Applet entry: routes ISO7816 Type 4 (NDEF) and NXP (0x90) command sets.
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.RandomData;

public final class Ntag424Applet extends Applet {
    private final Type4Handler t4t;
    private final NxpHandler nxp;

    public static void install(byte[] buf, short off, byte len) {
        short pos = off;
        byte lenAid = buf[pos++];
        short offAid = pos;
        pos += lenAid;
        byte lenCi = buf[pos++];
        pos += lenCi;
        byte lenAd = buf[pos++];
        short offAd = pos;

        Ntag424Applet applet = new Ntag424Applet(buf, offAd, lenAd);
        applet.register(buf, offAid, lenAid);
    }

    private Ntag424Applet(byte[] install, short installOff, byte installLen) {
        byte[] uid = new byte[Ntag424Constants.UID_LEN];
        byte[] keys = new byte[(short) (Ntag424Constants.NUM_KEYS * 16)];
        byte[] keyVersions = new byte[Ntag424Constants.NUM_KEYS];
        byte[] ccFile = new byte[Ntag424Constants.CC_FILE_SIZE];
        byte[] ndefFile = new byte[Ntag424Constants.NDEF_FILE_SIZE];
        byte[] propFile = new byte[Ntag424Constants.PROP_FILE_SIZE];
        byte[] origSig = new byte[Ntag424Constants.ORIG_SIG_LEN];
        byte[] ridSalt = new byte[InstallParams.RID_SALT_LEN];

        UtilCompat.arrayFillNonAtomic(keys, (short) 0, (short) keys.length, (byte) 0);
        InstallParams.load(uid, (short) 0, origSig, (short) 0, install, installOff, installLen);
        InstallParams.deriveRidSalt(uid, (short) 0, ridSalt, (short) 0);

        Type4Handler.buildCcFile(ccFile, Ntag424Constants.NDEF_FILE_SIZE);

        PiccConfig piccConfig = new PiccConfig();
        piccConfig.applyDefaults();

        FileSettings ccSettings = new FileSettings();
        ccSettings.fileSize = Ntag424Constants.CC_FILE_SIZE;
        ccSettings.commMode = Ntag424Constants.COMM_PLAIN;
        ccSettings.readPerm = Ntag424Constants.ACCESS_EVERYONE;
        ccSettings.writePerm = Ntag424Constants.ACCESS_NONE;

        FileSettings ndefSettings = new FileSettings();
        ndefSettings.fileSize = Ntag424Constants.NDEF_FILE_SIZE;
        ndefSettings.commMode = Ntag424Constants.COMM_PLAIN;
        ndefSettings.readPerm = Ntag424Constants.ACCESS_EVERYONE;
        ndefSettings.writePerm = Ntag424Constants.ACCESS_EVERYONE;
        ndefSettings.readWritePerm = Ntag424Constants.ACCESS_EVERYONE;
        ndefSettings.changePerm = Ntag424Constants.ACCESS_EVERYONE;

        FileSettings propSettings = new FileSettings();
        propSettings.fileSize = Ntag424Constants.PROP_FILE_SIZE;
        propSettings.commMode = Ntag424Constants.COMM_FULL;
        propSettings.readPerm = 0x02;
        propSettings.writePerm = 0x03;
        propSettings.readWritePerm = 0x03;
        propSettings.changePerm = (byte) 0x0F;
        propFile[0] = 0x5A;
        propFile[1] = (byte) 0xA5;

        CryptoWork crypto = new CryptoWork();
        AesHelper aes = new AesHelper(crypto);
        AesCmac cmac = new AesCmac(crypto);
        RandomData rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        LrpPrimitive lrp = new LrpPrimitive(aes, crypto);
        SdmHandler sdm = new SdmHandler(aes, cmac, lrp, crypto);
        byte[] scratch = new byte[Ntag424Constants.NDEF_FILE_SIZE];
        byte[] sdmCache = new byte[Ntag424Constants.NDEF_FILE_SIZE];
        byte[] piccPad = new byte[16];
        SdmSession sdmSession = new SdmSession(sdmCache, piccPad);
        FileStore extraFiles = new FileStore();
        AuthSession session = new AuthSession(aes, cmac, lrp, rng, crypto);

        t4t = new Type4Handler(ccFile, ndefFile, propFile, ccSettings, ndefSettings, propSettings,
            session, sdmSession, piccConfig);
        nxp = new NxpHandler(uid, ridSalt, keys, keyVersions, ccFile, ndefFile, propFile, origSig,
            ccSettings, ndefSettings, propSettings, extraFiles, piccConfig, session, aes,
            sdm, sdmSession, t4t, scratch, rng);
        t4t.bindNxp(nxp);
    }

    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        if (selectingApplet()) {
            t4t.reset();
            nxp.reset();
            return;
        }

        if (apdu.isSecureMessagingCLA()) {
            ISOException.throwIt(ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED);
        }

        byte cla = buffer[ISO7816.OFFSET_CLA];
        if (cla == Ntag424Constants.CLA_NXP) {
            nxp.process(apdu);
            return;
        }

        if (apdu.isISOInterindustryCLA()) {
            t4t.process(apdu);
            return;
        }

        ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    }

    public void deselect() {
        t4t.reset();
        nxp.reset();
    }
}
