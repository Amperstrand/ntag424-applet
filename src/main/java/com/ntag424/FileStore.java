package com.ntag424;

// Dynamic standard-data files 04-05 (128 B each); native 90 AD/8D only.
public final class FileStore {
    private final byte[] slot0;
    private final byte[] slot1;
    private final FileSettings[] settings;
    private final boolean[] allocated;

    public FileStore() {
        slot0 = new byte[Ntag424Constants.EXTRA_FILE_SIZE];
        slot1 = new byte[Ntag424Constants.EXTRA_FILE_SIZE];
        settings = new FileSettings[Ntag424Constants.NUM_EXTRA_FILES];
        allocated = new boolean[Ntag424Constants.NUM_EXTRA_FILES];
        for (byte i = 0; i < Ntag424Constants.NUM_EXTRA_FILES; i++) {
            settings[i] = new FileSettings();
        }
    }

    public short slotIndex(byte fileNum) {
        if (fileNum < Ntag424Constants.FILE_EXTRA_BASE) {
            return -1;
        }
        short idx = (short) (fileNum - Ntag424Constants.FILE_EXTRA_BASE);
        if (idx >= Ntag424Constants.NUM_EXTRA_FILES) {
            return -1;
        }
        return idx;
    }

    public boolean isAllocated(byte fileNum) {
        short idx = slotIndex(fileNum);
        return idx >= 0 && allocated[idx];
    }

    public FileSettings getSettings(byte fileNum) {
        short idx = slotIndex(fileNum);
        if (idx < 0 || !allocated[idx]) {
            return null;
        }
        return settings[idx];
    }

    public byte[] getFile(byte fileNum) {
        short idx = slotIndex(fileNum);
        if (idx < 0 || !allocated[idx]) {
            return null;
        }
        return idx == 0 ? slot0 : slot1;
    }

    public boolean create(byte fileNum, byte[] plain, short off, short len) {
        short idx = slotIndex(fileNum);
        if (idx < 0 || allocated[idx] || len < 7) {
            return false;
        }
        if (plain[off] != Ntag424Constants.FILE_TYPE_STD) {
            return false;
        }
        byte options = plain[(short) (off + 1)];
        if ((options & 0xFC) != 0) {
            return false;
        }
        byte comm = (byte) (options & 0x03);
        if (comm != Ntag424Constants.COMM_PLAIN
                && comm != Ntag424Constants.COMM_MAC
                && comm != Ntag424Constants.COMM_FULL) {
            return false;
        }
        short size = UtilCompat.getOffset3(plain, (short) (off + 4));
        if (size <= 0 || size > Ntag424Constants.EXTRA_FILE_SIZE) {
            return false;
        }

        FileSettings fs = settings[idx];
        fs.commMode = comm;
        fs.readWritePerm = (byte) ((plain[(short) (off + 2)] >> 4) & 0x0F);
        fs.changePerm = (byte) (plain[(short) (off + 2)] & 0x0F);
        fs.readPerm = (byte) ((plain[(short) (off + 3)] >> 4) & 0x0F);
        fs.writePerm = (byte) (plain[(short) (off + 3)] & 0x0F);
        fs.fileSize = size;
        fs.sdmEnabled = false;
        fs.readCounter = 0;

        byte[] buf = idx == 0 ? slot0 : slot1;
        UtilCompat.arrayFillNonAtomic(buf, (short) 0, Ntag424Constants.EXTRA_FILE_SIZE, (byte) 0);
        allocated[idx] = true;
        return true;
    }

    public void delete(byte fileNum) {
        short idx = slotIndex(fileNum);
        if (idx < 0 || !allocated[idx]) {
            return;
        }
        allocated[idx] = false;
        FileSettings fs = settings[idx];
        fs.commMode = Ntag424Constants.COMM_PLAIN;
        fs.readPerm = Ntag424Constants.ACCESS_EVERYONE;
        fs.writePerm = Ntag424Constants.ACCESS_EVERYONE;
        fs.readWritePerm = Ntag424Constants.ACCESS_EVERYONE;
        fs.changePerm = Ntag424Constants.ACCESS_EVERYONE;
        fs.fileSize = 0;
        fs.sdmEnabled = false;
        fs.readCounter = 0;
    }
}
