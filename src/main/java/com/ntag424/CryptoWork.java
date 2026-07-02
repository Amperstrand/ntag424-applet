package com.ntag424;

// Shared transient crypto buffers (one instance per applet).
public final class CryptoWork {
    final byte[] block16 = new byte[16];
    final byte[] sessionKey = new byte[16];
    final byte[] sv32 = new byte[32];
    final byte[] macInput = new byte[280];
}
