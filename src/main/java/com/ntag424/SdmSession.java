package com.ntag424;

import javacard.security.RandomData;

// SDM read-burst state: ISOReadBinary vs ReadData bump counter independently (AN12196 9.3.1).
public final class SdmSession {
    public static final byte CH_ISO = 1;
    public static final byte CH_NATIVE = 2;

    private final byte[] cache;
    private final byte[] piccPad;
    private boolean isoPrepared;
    private boolean nativePrepared;
    private boolean isoChainOpen;

    public SdmSession(byte[] cache, byte[] piccPad) {
        this.cache = cache;
        this.piccPad = piccPad;
    }

    public byte[] cache() {
        return cache;
    }

    public byte[] piccPad() {
        return piccPad;
    }

    public boolean isPrepared(byte channel) {
        if (channel == CH_ISO) {
            return isoPrepared;
        }
        if (channel == CH_NATIVE) {
            return nativePrepared;
        }
        return false;
    }

    public void markPrepared(byte channel) {
        if (channel == CH_ISO) {
            isoPrepared = true;
        } else if (channel == CH_NATIVE) {
            nativePrepared = true;
        }
    }

    public void invalidate() {
        isoPrepared = false;
        nativePrepared = false;
        isoChainOpen = false;
    }

    public void beginIsoChain() {
        isoChainOpen = true;
    }

    public void endIsoChain() {
        isoChainOpen = false;
    }

    public boolean isoChainOpen() {
        return isoChainOpen;
    }

    public void freshPiccPad(RandomData rng) {
        rng.generateData(piccPad, (short) 0, (short) 16);
    }
}
