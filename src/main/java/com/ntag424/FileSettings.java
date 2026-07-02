package com.ntag424;

// Per-file access mode, permissions, and SDM mirror settings.
public final class FileSettings {
    public byte commMode = Ntag424Constants.COMM_PLAIN;
    public byte readPerm = Ntag424Constants.ACCESS_EVERYONE;
    public byte writePerm = Ntag424Constants.ACCESS_EVERYONE;
    public byte readWritePerm = Ntag424Constants.ACCESS_EVERYONE;
    public byte changePerm = Ntag424Constants.ACCESS_EVERYONE;
    public short fileSize;

    public boolean sdmEnabled;
    public boolean sdmUid;
    public boolean sdmReadCounter;
    public boolean sdmReadCounterLimit;
    public boolean sdmEncryptFileData;
    public boolean sdmUseAscii = true;

    public byte sdmMetaReadPerm = Ntag424Constants.ACCESS_EVERYONE;
    public byte sdmFileReadPerm = Ntag424Constants.ACCESS_EVERYONE;
    public byte sdmReadCounterRetrievalPerm = Ntag424Constants.ACCESS_NONE;

    public short sdmUidOffset;
    public short sdmReadCounterOffset;
    public boolean sdmCounterMirrored = true;
    public short sdmPiccDataOffset;
    public short sdmMacInputOffset;
    public short sdmEncOffset;
    public short sdmEncLength;
    public short sdmMacOffset;
    public short sdmMaxReadCounter;

    public short readCounter;

    // ChangeFileSettings payload (no file type/size prefix).
    public void decodeMutable(byte[] data, short off, short len) {
        byte options = data[(short) (off + 1)];
        sdmEnabled = (options & 0x40) != 0;
        commMode = (byte) (options & 0x03);

        readWritePerm = (byte) ((data[(short) (off + 2)] >> 4) & 0x0F);
        changePerm = (byte) (data[(short) (off + 2)] & 0x0F);
        readPerm = (byte) ((data[(short) (off + 3)] >> 4) & 0x0F);
        writePerm = (byte) (data[(short) (off + 3)] & 0x0F);

        decodeSdm(data, (short) (off + 4), (short) (off + len));
    }

    private void decodeSdm(byte[] data, short pos, short end) {
        if (!sdmEnabled || pos >= end) {
            return;
        }

        byte sdmOptions = data[pos++];
        sdmUid = (sdmOptions & 0x80) != 0;
        sdmReadCounter = (sdmOptions & 0x40) != 0;
        sdmReadCounterLimit = (sdmOptions & 0x20) != 0;
        sdmEncryptFileData = (sdmOptions & 0x10) != 0;
        sdmUseAscii = (sdmOptions & 0x01) != 0;

        byte sdmRights2 = data[pos++];
        byte sdmRights1 = data[pos++];
        sdmMetaReadPerm = (byte) ((sdmRights1 >> 4) & 0x0F);
        sdmFileReadPerm = (byte) (sdmRights1 & 0x0F);
        sdmReadCounterRetrievalPerm = (byte) (sdmRights2 & 0x0F);

        if (sdmMetaReadPerm == Ntag424Constants.ACCESS_EVERYONE) {
            if (sdmUid) {
                sdmUidOffset = UtilCompat.getOffset3(data, pos);
                pos = (short) (pos + 3);
            }
            if (sdmReadCounter) {
                sdmCounterMirrored = !Ntag424Constants.isSdmOffsetDisabled(data, pos);
                sdmReadCounterOffset = UtilCompat.getOffset3(data, pos);
                pos = (short) (pos + 3);
            }
        } else if (sdmMetaReadPerm != Ntag424Constants.ACCESS_NONE) {
            sdmPiccDataOffset = UtilCompat.getOffset3(data, pos);
            pos = (short) (pos + 3);
        }

        if (sdmFileReadPerm != Ntag424Constants.ACCESS_NONE) {
            sdmMacInputOffset = UtilCompat.getOffset3(data, pos);
            pos = (short) (pos + 3);
            if (sdmEncryptFileData) {
                sdmEncOffset = UtilCompat.getOffset3(data, pos);
                pos = (short) (pos + 3);
                sdmEncLength = UtilCompat.getOffset3(data, pos);
                pos = (short) (pos + 3);
            }
            sdmMacOffset = UtilCompat.getOffset3(data, pos);
            pos = (short) (pos + 3);
        }

        if (sdmReadCounterLimit && pos < end) {
            sdmMaxReadCounter = UtilCompat.getOffset3(data, pos);
        }
    }

    public short encodeFull(byte fileType, byte[] out, short off) {
        short pos = off;
        out[pos++] = fileType;
        byte options = (byte) (commMode | (sdmEnabled ? 0x40 : 0));
        out[pos++] = options;
        out[pos++] = (byte) ((readWritePerm << 4) | changePerm);
        out[pos++] = (byte) ((readPerm << 4) | writePerm);
        UtilCompat.setOffset3(out, pos, fileSize);
        pos = (short) (pos + 3);

        if (sdmEnabled) {
            byte sdmOptions = 0;
            if (sdmUid) sdmOptions |= 0x80;
            if (sdmReadCounter) sdmOptions |= 0x40;
            if (sdmReadCounterLimit) sdmOptions |= 0x20;
            if (sdmEncryptFileData) sdmOptions |= 0x10;
            if (sdmUseAscii) sdmOptions |= 0x01;
            out[pos++] = sdmOptions;

            out[pos++] = (byte) (0xF0 | (sdmReadCounter ? sdmReadCounterRetrievalPerm : 0x0F));
            out[pos++] = (byte) ((sdmMetaReadPerm << 4) | sdmFileReadPerm);

            if (sdmMetaReadPerm == Ntag424Constants.ACCESS_EVERYONE) {
                if (sdmUid) {
                    UtilCompat.setOffset3(out, pos, sdmUidOffset);
                    pos = (short) (pos + 3);
                }
                if (sdmReadCounter) {
                    if (sdmCounterMirrored) {
                        UtilCompat.setOffset3(out, pos, sdmReadCounterOffset);
                    } else {
                        UtilCompat.setOffset3Disabled(out, pos);
                    }
                    pos = (short) (pos + 3);
                }
            } else if (sdmMetaReadPerm != Ntag424Constants.ACCESS_NONE) {
                UtilCompat.setOffset3(out, pos, sdmPiccDataOffset);
                pos = (short) (pos + 3);
            }

            if (sdmFileReadPerm != Ntag424Constants.ACCESS_NONE) {
                UtilCompat.setOffset3(out, pos, sdmMacInputOffset);
                pos = (short) (pos + 3);
                if (sdmEncryptFileData) {
                    UtilCompat.setOffset3(out, pos, sdmEncOffset);
                    pos = (short) (pos + 3);
                    UtilCompat.setOffset3(out, pos, sdmEncLength);
                    pos = (short) (pos + 3);
                }
                UtilCompat.setOffset3(out, pos, sdmMacOffset);
                pos = (short) (pos + 3);
            }

            if (sdmReadCounterLimit) {
                UtilCompat.setOffset3(out, pos, sdmMaxReadCounter);
                pos = (short) (pos + 3);
            }
        }

        return (short) (pos - off);
    }
}
