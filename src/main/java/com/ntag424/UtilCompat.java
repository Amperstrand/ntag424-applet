package com.ntag424;

// Thin wrappers around javacard.framework.Util (3-byte LSB wire helpers for SDM offsets).
import javacard.framework.Util;

public final class UtilCompat {
    private UtilCompat() {}

    public static void arrayCopy(byte[] src, short srcOff, byte[] dst, short dstOff, short len) {
        Util.arrayCopy(src, srcOff, dst, dstOff, len);
    }

    public static void arrayCopyNonAtomic(byte[] src, short srcOff, byte[] dst, short dstOff, short len) {
        Util.arrayCopyNonAtomic(src, srcOff, dst, dstOff, len);
    }

    public static void arrayFillNonAtomic(byte[] buf, short off, short len, byte val) {
        Util.arrayFillNonAtomic(buf, off, len, val);
    }

    public static short setShort(byte[] buf, short off, short val) {
        return Util.setShort(buf, off, val);
    }

    public static short getShort(byte[] buf, short off) {
        return Util.getShort(buf, off);
    }

    public static short getShortLE(byte[] buf, short off) {
        return (short) ((buf[off] & 0xFF) | ((buf[(short) (off + 1)] & 0xFF) << 8));
    }

    public static byte getByteLSB(short val, byte index) {
        return (byte) ((val >> (index * 8)) & 0xFF);
    }

    public static short getOffset3(byte[] buf, short off) {
        return (short) ((buf[off] & 0xFF)
            | ((buf[(short) (off + 1)] & 0xFF) << 8)
            | ((buf[(short) (off + 2)] & 0xFF) << 16));
    }

    public static void setOffset3(byte[] buf, short off, short val) {
        buf[off] = getByteLSB(val, (byte) 0);
        buf[(short) (off + 1)] = getByteLSB(val, (byte) 1);
        buf[(short) (off + 2)] = 0;
    }

    public static void setOffset3Disabled(byte[] buf, short off) {
        buf[off] = (byte) 0xFF;
        buf[(short) (off + 1)] = (byte) 0xFF;
        buf[(short) (off + 2)] = (byte) 0xFF;
    }

    public static boolean arrayEqual(byte[] a, short aOff, byte[] b, short bOff, short len) {
        return Util.arrayCompare(a, aOff, b, bOff, len) == 0;
    }
}
