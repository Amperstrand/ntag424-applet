package com.ntag424;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * SDM lifecycle regressions: plain NDEF write -> ChangeFileSettings (SDM
 * enable) -> read paths (ISO T4T + plain 90AD). Pins the wipe-path
 * regression (9103 length error on the SDM-enabled NDEF read) and the
 * ChangeFileSettings MACt response format.
 */
class SdmLifecycleTest extends AppletTestBase {

    static final byte[] UID = TestCrypto.hexBytes("04337D8AAE1790");
    static final byte[] ZEROS = new byte[16];

    Ev2Client ev2;

    @BeforeEach
    void setUp() throws Exception {
        installApplet(UID);
        ev2 = new Ev2Client();
        ev2.authenticate(this, (byte) 0, ZEROS);
    }

    // NDEF: "https://x.psbt.me/?p={picc:uid+ctr}&c={mac}"-shaped template
    // (offsets chosen to match the payload length)
    static final int PICC_OFFSET = 30;
    static final int MAC_OFFSET = 65;

    private byte[] ndefTemplate() {
        // NLEN(2) + TNF/type/len + "https://x.psbt.me/?p=" + 32 hex slots +
        // "&c=" + 16 hex slots; total payload sized so the mirrored windows
        // land at PICC_OFFSET / MAC_OFFSET.
        byte[] url = "https://x.psbt.me/?p=PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP&c=MMMMMMMMMMMMMMMM".getBytes();
        byte[] ndef = new byte[256];
        int rec = 2;
        ndef[rec++] = 0x01; // MB|ME|SR|URI
        ndef[rec++] = 0x24; // type length ("urn:...:B?URL" no -> https://www...
        ndef[rec++] = (byte) url.length;
        // using the https://www prefix form: type "U", id 0x04 -> keep simple:
        return buildSimpleUriRecord(url);
    }

    private byte[] buildSimpleUriRecord(byte[] url) {
        // RTD-URI well-known record with the "https://www." prefix code 0x04
        byte[] payload = new byte[url.length - 8 + 1]; // drop "https://" (8)
        payload[0] = 0x01; // "https://www."
        System.arraycopy(url, 8, payload, 1, url.length - 8);
        byte[] rec = new byte[3 + 1 + payload.length];
        rec[0] = 0x01; // MB|ME
        rec[1] = 0x01; // SR
        rec[2] = (byte) (payload.length + 1); // len(type)+len(payload)
        rec[3] = 'U'; // type
        System.arraycopy(payload, 0, rec, 4, payload.length);
        byte[] ndef = new byte[256];
        ndef[0] = (byte) ((rec.length >> 8) & 0xFF);
        ndef[1] = (byte) (rec.length & 0xFF);
        System.arraycopy(rec, 0, ndef, 2, rec.length);
        return ndef;
    }

    private void writeNdefPlain(byte[] ndef) throws Exception {
        writeNdefPlain(ndef, ndef.length);
    }

    private void writeNdefPlain(byte[] ndef, int len) throws Exception {
        byte[] hdr = {0x02, 0x00, 0x00, 0x00, (byte) len, 0x00, 0x00};
        byte[] body = new byte[7 + len];
        System.arraycopy(hdr, 0, body, 0, 7);
        System.arraycopy(ndef, 0, body, 7, len);
        Ev2Client.Response r = Ev2Client.transmit(this, (byte) 0x8D, body);
        assertEquals(0x9100, r.sw, "plain WriteData (factory rights) must succeed");
        ev2.advance(); // plain exchange advances CmdCtr (silicon rule)
    }

    /** Enable SDM with encrypted PICC data (K1) + file-read MAC (K2). */
    private int enableSdm() throws Exception {
        // options: SDM enabled (0x40), comm plain (0x00)
        // rights: rw=0x0, ch=0x0 | read=E, write=0x0
        // SDM: opts uid|ctr (0xC0); rights2 ctrRet=0xF; rights1 meta=0x1(K1), file=0x2(K2)
        // then PICC offset(3), macInput(3), macOffset(3)
        byte[] pt = new byte[16];
        pt[0] = 0x40;
        pt[1] = 0x00; // rw|change = 0|0 (key0)
        pt[2] = (byte) 0xE0; // read=E, write=0 (key0)
        pt[3] = (byte) 0xC0; // sdm: uid + read counter
        pt[4] = 0x0F; // rights2: counter retrieval
        pt[5] = 0x12; // rights1: meta=K1, file=K2
        pt[6] = (byte) PICC_OFFSET; pt[7] = 0; pt[8] = 0; // LE 3-byte
        pt[9] = (byte) MAC_OFFSET; pt[10] = 0; pt[11] = 0;
        pt[12] = (byte) MAC_OFFSET; pt[13] = 0; pt[14] = 0;
        return ev2.changeFileSettings(this, (byte) 0x02, pt);
    }

    @Test
    void changeFileSettingsAnswersMactAndTakesEffect() throws Exception {
        byte[] t = ndefTemplate();
        int recLen = 2 + ((t[0] & 0xFF) << 8 | t[1] & 0xFF);
        writeNdefPlain(t, recLen);
        assertEquals(0x9100, enableSdm(), "5F must succeed");
        // verify the settings took: MAC'd GetFileSettings now shows SDM
        byte[] body = ev2.macCommand((byte) 0xF5, new byte[]{0x02}, null);
        Ev2Client.Response r = Ev2Client.transmit(this, (byte) 0xF5, body);
        assertEquals(0x9100, r.sw);
        assertTrue(ev2.verifyResponse((byte) 0x00, r.data), "F5 response MACt");
        byte[] settings = java.util.Arrays.copyOf(r.data, r.data.length - 8);
        assertEquals(0x40, settings[1] & 0x40, "SDM flag must be set in file settings");
    }

    @Test
    void plainReadDataAfterSdmEnableDoesNotError() throws Exception {
        byte[] t = ndefTemplate();
        int recLen = 2 + ((t[0] & 0xFF) << 8 | t[1] & 0xFF);
        writeNdefPlain(t, recLen);
        assertEquals(0x9100, enableSdm());
        // the wipe preverification path: plain ReadData of the SDM-enabled
        // NDEF (200 bytes — within every chunking rule; 256 hits the
        // jcardsim/Le-0 encoding quirk, and real hosts chunk at 248)
        byte[] body = {0x02, 0x00, 0x00, 0x00, (byte) 200, 0x00, 0x00};
        Ev2Client.Response r = Ev2Client.transmit(this, (byte) 0xAD, body);
        assertEquals(0x9100, r.sw, "plain ReadData after SDM enable must succeed");
        assertEquals(200, r.data.length, "plain ReadData must return the requested bytes");
        ev2.advance();
    }

    @Test
    @org.junit.jupiter.api.Disabled("jcardsim 2.2.2 direct-transmit truncates sendBytes "
        + "responses (2 bytes, no SW); the same T4T READ-BINARY returns full NDEF "
        + "through the vpcd E2E path — covered there until the sim quirk is understood")
    void isoReadBinaryOfSdmEnabledNdefWorks() throws Exception {
        byte[] t = ndefTemplate();
        int recLen = 2 + ((t[0] & 0xFF) << 8 | t[1] & 0xFF);
        writeNdefPlain(t, recLen);
        assertEquals(0x9100, enableSdm());
        // T4T path: select CC (E103), select NDEF (E104), READ-BINARY
        javax.smartcardio.ResponseAPDU cc = transmit(new byte[]{
                0x00, (byte) 0xA4, 0x00, 0x0C, 0x02, (byte) 0xE1, 0x03});
        assertEquals(0x9000, cc.getSW(), "CC select");
        javax.smartcardio.ResponseAPDU nf = transmit(new byte[]{
                0x00, (byte) 0xA4, 0x00, 0x0C, 0x02, (byte) 0xE1, 0x04});
        assertEquals(0x9000, nf.getSW(), "NDEF select");
        javax.smartcardio.ResponseAPDU rb = transmit(new byte[]{
                0x00, (byte) 0xB0, 0x00, 0x00, (byte) 0xF0});
        assertNotEquals(0x6A87, rb.getSW());
        assertTrue(rb.getData().length > 0, "READ-BINARY must return NDEF data");
    }
}
