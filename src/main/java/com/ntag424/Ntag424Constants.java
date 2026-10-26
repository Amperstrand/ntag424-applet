package com.ntag424;

// Command codes, file IDs, and default sizes for the NTAG 424 DNA emulation.
public final class Ntag424Constants {
    private Ntag424Constants() {}

    public static final byte CLA_NXP = (byte) 0x90;

    public static final byte[] DF_NAME = {
        (byte) 0xD2, 0x76, 0x00, 0x00, (byte) 0x85, 0x01, 0x01
    };
    public static final byte DF_NAME_LEN = 7;
    public static final byte[] APP_ID = {(byte) 0xD2, 0x76, 0x00};
    public static final byte APP_ID_LEN = 3;

    public static final short FID_DF = (short) 0xE110;
    public static final short FID_CC = (short) 0xE103;
    public static final short FID_NDEF = (short) 0xE104;

    public static final byte FILE_CC = 0x01;
    public static final byte FILE_NDEF = 0x02;
    public static final byte FILE_PROPRIETARY = 0x03;

    public static final byte FILE_EXTRA_BASE = 0x04;
    public static final byte NUM_EXTRA_FILES = 2;
    public static final short EXTRA_FILE_SIZE = 128;

    public static final short FID_PROPRIETARY = (short) 0xE105;

    public static final short CC_FILE_SIZE = 32;
    public static final short NDEF_FILE_SIZE = 416;
    public static final short PROP_FILE_SIZE = 128;

    public static final short NDEF_CC_MLE = 416;
    public static final short NDEF_CC_MLC = 416;
    public static final short NDEF_READ_MAX = 416;
    public static final byte NDEF_MAPPING_VERSION = (byte) 0x20;

    public static final byte CMD_AUTH_EV2_FIRST = 0x71;
    public static final byte CMD_AUTH_EV2_NONFIRST = 0x77;
    public static final byte CMD_ADDITIONAL_FRAME = (byte) 0xAF;
    public static final byte CMD_READ_DATA = (byte) 0xAD;
    public static final byte CMD_WRITE_DATA = (byte) 0x8D;
    public static final byte CMD_GET_FILE_SETTINGS = (byte) 0xF5;
    public static final byte CMD_SET_CONFIGURATION = 0x5C;
    public static final byte CMD_CHANGE_FILE_SETTINGS = 0x5F;
    public static final byte CMD_CHANGE_KEY = (byte) 0xC4;
    // Optional: used by ChangeKey to store key version byte.
    public static final byte CMD_GET_KEY_VERSION = 0x64;

    public static final byte CMD_GET_READ_COUNTER = (byte) 0xF6;
    public static final byte CMD_SET_CARD_UID = 0x52; // JavaCard-only; main.py personalize after auth

    public static final byte COMM_PLAIN = 0x00;
    public static final byte COMM_MAC = 0x01;
    public static final byte COMM_FULL = 0x03;

    public static final byte ACCESS_EVERYONE = (byte) 0x0E;
    public static final byte ACCESS_NONE = (byte) 0x0F;

    public static final byte NUM_KEYS = 5;
    public static final byte ORIGINALITY_KEY_FIRST = 0x01;
    public static final byte ORIGINALITY_KEY_LAST = 0x04;
    public static final byte UID_LEN = 7;

    public static boolean isOriginalityKey(byte keyNum) {
        return keyNum >= ORIGINALITY_KEY_FIRST && keyNum <= ORIGINALITY_KEY_LAST;
    }

    public static boolean isSdmOffsetDisabled(byte[] data, short off) {
        return data[off] == (byte) 0xFF
            && data[(short) (off + 1)] == (byte) 0xFF
            && data[(short) (off + 2)] == (byte) 0xFF;
    }

    public static final byte SW_ADDITIONAL_FRAME = (byte) 0xAF;
    public static final byte SW_OK = (byte) 0x00;
    public static final byte SW_READ_SIG_OK = (byte) 0x90; // real silicon returns 9190, not 9100
    public static final byte SW_NXP_OK = (byte) 0x91;

    public static final byte FILE_TYPE_STD = 0x00;

    public static final byte CMD_GET_VERSION = 0x60;
    public static final byte CMD_GET_APPLICATION_IDS = 0x6A;
    public static final byte CMD_SELECT_APPLICATION = 0x5A;
    public static final byte CMD_GET_CARD_UID = 0x51;
    public static final byte CMD_READ_SIG = 0x3C;
    public static final byte CMD_CREATE_FILE = (byte) 0xCD;
    public static final byte CMD_DELETE_FILE = (byte) 0xDF;

    public static final byte ORIG_SIG_LEN = 56;
  // ponytail: stable emulator default; override via gp --params UID+sig or program_card --orig-sig
    public static final byte[] DEFAULT_ORIG_SIG = {
        (byte) 0xA1, (byte) 0xB2, (byte) 0xC3, (byte) 0xD4, (byte) 0xE5, (byte) 0xF6, 0x07, 0x18,
        0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, (byte) 0x8F, (byte) 0x90,
        (byte) 0xA1, (byte) 0xB2, (byte) 0xC3, (byte) 0xD4, (byte) 0xE5, (byte) 0xF6, 0x07, 0x18,
        0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, (byte) 0x8F, (byte) 0x90,
        0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, (byte) 0x89,
        (byte) 0x9A, (byte) 0xAB, (byte) 0xBC, (byte) 0xCD, (byte) 0xDE, (byte) 0xEF, (byte) 0xF0, 0x01,
        0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, (byte) 0x89
    };
    public static final byte SW_INTEGRITY_ERROR = 0x1E;

    public static final byte VERSION_INFO_LEN = 7;
    public static final byte PRODUCTION_INFO_LEN = 28;
    public static final byte VERSION_PRODUCTION_UID_OFFSET = 0;
    // ponytail: tail verified on bare NTAG424 (CD65935D402118…); UID patched at runtime. Re-capture: capture_get_version.py --mode physical --java
    public static final byte[] VERSION_PRODUCTION = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        (byte) 0xCD, 0x65, (byte) 0x93, 0x5D,
        0x40, 0x21, 0x18,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    public static final byte[] VERSION_HW = {0x04, 0x04, 0x02, 0x01, 0x00, 0x1A, 0x05};
    public static final byte[] VERSION_SW = {0x04, 0x04, 0x02, 0x00, 0x11, 0x05, 0x05};
    public static final byte SW_DESFIRE_APP_NOT_FOUND = (byte) 0xA0;
    public static final byte SW_FILE_EXISTS = (byte) 0xF0;
    public static final byte SW_LENGTH_ERROR = (byte) 0x7E;
    public static final byte SW_PARAMETER_ERROR = (byte) 0x9E;
    public static final byte SW_AUTHENTICATION_ERROR = (byte) 0xAE;
    public static final byte SW_AUTHENTICATION_DELAY = (byte) 0xAD;
    public static final byte SW_BOUNDARY_ERROR = (byte) 0xBE;
    public static final byte SW_NOT_ALLOWED = (byte) 0x1C;
    // 0xF0 on silicon = "file not found" (NXP SW space); the existing
    // SW_FILE_EXISTS name is a misnomer — value verified on real silicon
    public static final byte SW_FILE_NOT_FOUND = (byte) 0xF0;

    public static final byte AUTH_MODE_LRP = 0x01;
    public static final byte PCD_CAP2_LEN = 6;
    public static final byte LRP_ENC_CTR_NIBBLES = 8;
    public static final byte LRP_SDM_CTR_NIBBLES = 12;
}
