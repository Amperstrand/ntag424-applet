package com.ntag424;

// PICC-level config (SetConfiguration options 00 / 04 / 05 / 0A / 0B).
public final class PiccConfig {
    public boolean lrpEnabled;
    public boolean randomIdEnabled;
    public boolean disableChainedWrite;
    public boolean failCtrEnabled = true;
    public short failCtrLimit = 1000;
    public short failCtrDecr = 10;
    public short failCtrCurrent = 0;

    private static final byte SEQ_FAIL_DELAY_START = 50;
    // JC222 (build.xml targetsdk=jc222_kit): no JCSystem.getTransactionTime in SDK exports.
    // authDelayRemaining counts stage-1 polls; wall time does not advance the delay window.
    // Probe: tools/probe_jcop_timer.py. Upgrade: JC 3.x getTransactionTime -> authDelayUntilMs.
    private byte seqFailCtr;
    private short authDelayRemaining;

    public static final byte OPT_PICC = 0x00;
    public static final byte OPT_SM_CONFIG = 0x04;
    public static final byte OPT_CAPABILITY = 0x05;
    public static final byte OPT_FAIL_CTR = 0x0A;
    public static final byte OPT_HW = 0x0B;
    public static final byte PICC_LEN = 1;
    public static final byte SM_CONFIG_LEN = 2;
    public static final byte CAPABILITY_LEN = 10;
    public static final byte FAIL_CTR_LEN = 5;
    public static final byte HW_LEN = 1;
    public static final byte PDCAP21_LRP_BIT = 0x02;
    public static final byte PICC_RID_BIT = 0x02;

    public void applyDefaults() {
        failCtrEnabled = true;
        failCtrLimit = 1000;
        failCtrDecr = 10;
        failCtrCurrent = 0;
        seqFailCtr = 0;
        authDelayRemaining = 0;
    }

    public boolean applyPicc(byte config) {
        if ((config & (byte) 0xF9) != 0) {
            return false;
        }
        if ((config & PICC_RID_BIT) != 0) {
            randomIdEnabled = true;
        }
        return true;
    }

    public boolean applySmConfig(byte[] data, short off) {
        if ((data[off] & (byte) 0xF8) != 0) {
            return false;
        }
        if ((data[off] & 0x04) != 0) {
            disableChainedWrite = true;
        }
        if ((data[(short) (off + 1)] & (byte) 0xFC) != 0) {
            return false;
        }
        return true;
    }

    public boolean applyCapability(byte[] data, short off) {
        byte pdcap21 = data[(short) (off + 4)];
        if ((pdcap21 & (byte) 0xFC) != 0) {
            return false;
        }
        if ((pdcap21 & PDCAP21_LRP_BIT) != 0) {
            lrpEnabled = true;
        }
        return true;
    }

    public boolean applyFailCtr(byte[] data, short off) {
        failCtrEnabled = (data[off] & 0x01) != 0;
        failCtrLimit = UtilCompat.getShortLE(data, (short) (off + 1));
        failCtrDecr = UtilCompat.getShortLE(data, (short) (off + 3));
        if (failCtrEnabled && failCtrLimit == 0) {
            return false;
        }
        failCtrCurrent = 0;
        seqFailCtr = 0;
        authDelayRemaining = 0;
        return true;
    }

    public byte authGateSw2(boolean originalityKey) {
        if (!failCtrEnabled || originalityKey) {
            return Ntag424Constants.SW_OK;
        }
        if (failCtrCurrent >= failCtrLimit) {
            return Ntag424Constants.SW_AUTHENTICATION_ERROR;
        }
        if (authDelayRemaining > 0) {
            authDelayRemaining--;
            return Ntag424Constants.SW_AUTHENTICATION_DELAY;
        }
        return Ntag424Constants.SW_OK;
    }

    public void onAuthFail(boolean originalityKey) {
        if (originalityKey || !failCtrEnabled || failCtrCurrent >= failCtrLimit) {
            return;
        }
        failCtrCurrent++;
        if (seqFailCtr < (byte) 127) {
            seqFailCtr++;
        }
        short delay = authDelayTicks();
        if (delay > 0 && delay > authDelayRemaining) {
            authDelayRemaining = delay;
        }
    }

    public void onAuthSuccess(boolean originalityKey) {
        if (!failCtrEnabled || originalityKey) {
            return;
        }
        seqFailCtr = 0;
        authDelayRemaining = 0;
        short next = (short) (failCtrCurrent - failCtrDecr);
        failCtrCurrent = next < 0 ? (short) 0 : next;
    }

    public boolean applyHw(byte config) {
        return (config & (byte) 0xFE) == 0;
    }

    // ponytail: poll ticks after 50 seq fails (steps*5 gate calls); not AN12196 SpentTimeCtr ms
    private short authDelayTicks() {
        if (seqFailCtr < SEQ_FAIL_DELAY_START) {
            return 0;
        }
        short steps = (short) (seqFailCtr - (SEQ_FAIL_DELAY_START - 1));
        if (steps > 50) {
            steps = 50;
        }
        return (short) (steps * 5);
    }
}
