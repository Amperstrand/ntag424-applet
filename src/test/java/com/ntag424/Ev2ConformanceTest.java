package com.ntag424;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * EV2 conformance regressions for the ntag424-applet fork — every test here
 * pins a behavior that was broken pre-fix (commits c98f5c4, 75bcc4a) and is
 * silicon-anchored by the spec quotes in the main sources.
 */
class Ev2ConformanceTest extends AppletTestBase {

    static final byte[] UID = TestCrypto.hexBytes("04337D8AAE1790");
    static final byte[] ZEROS = new byte[16];

    Ev2Client ev2;

    @BeforeEach
    void setUp() throws Exception {
        installApplet(UID);
        ev2 = new Ev2Client();
    }

    private void authZeros() throws Exception {
        ev2.authenticate(this, (byte) 0, ZEROS);
    }

    /** MAC'd GetFileSettings (INS F5, file 02). Returns sw. */
    private int getFileSettings() throws Exception {
        byte[] body = ev2.macCommand((byte) 0xF5, new byte[]{0x02}, null);
        Ev2Client.Response r = Ev2Client.transmit(this, (byte) 0xF5, body);
        if (r.sw != 0x9100) return r.sw;
        byte[] data = java.util.Arrays.copyOf(r.data, r.data.length - 8);
        assertTrue(ev2.verifyResponse((byte) 0x00, r.data), "response MACt must verify (ctr-locked)");
        return r.sw;
    }

    /** Plain ReadData (INS AD, file 02, offset 0, len 4). */
    private int plainRead() throws Exception {
        byte[] body = {0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00};
        Ev2Client.Response r = Ev2Client.transmit(this, (byte) 0xAD, body);
        if (r.sw == 0x9100 && ev2.active) {
            // silicon parity: EVERY authenticated-session command advances
            // CmdCtr, plain framing included (NT4H2421Gx 9.1.2)
            ev2.advance();
        }
        return r.sw;
    }

    @Test
    void authRoundTripSucceedsWithFactoryKey() {
        assertDoesNotThrow(this::authZeros);
    }

    /**
     * THE counter regression: plain exchanges inside an authenticated session
     * must advance CmdCtr on BOTH sides. Pre-fix the applet did not advance,
     * so the GetFileSettings after a plain ReadData failed 911E
     * (silicon: NT4H2421Gx 9.1.2; quotes: NTA_TESTS/NTA_SESSION in
     * NxpFileHandler).
     */
    @Test
    void plainExchangeAdvancesCommandCounter() throws Exception {
        authZeros();
        assertEquals(0x9100, getFileSettings(), "F5 #1 must succeed");
        assertEquals(0x9100, plainRead(), "plain read must succeed (free rights)");
        assertEquals(0x9100, getFileSettings(), "F5 #2 must succeed — counter stayed in lockstep");
        assertEquals(0x9100, plainRead(), "plain read #2");
        assertEquals(0x9100, getFileSettings(), "F5 #3");
        assertEquals(0x9100, plainRead(), "plain read #3");
    }

    /** Pre-fix: wrong-key AuthSecond answered ISO 6982; silicon answers 91AE. */
    @Test
    void wrongKeyAuthSecondAnswersNtagStatus() throws Exception {
        byte[] rndA = new byte[16];
        new java.security.SecureRandom().nextBytes(rndA);
        Ev2Client.Response r1 = Ev2Client.transmit(this, (byte) 0x71, new byte[]{0, 0x03, 0, 0, 0});
        assertEquals(0x91AF, r1.sw);
        byte[] rndB = Ev2Client.aesEcb(ZEROS, javax.crypto.Cipher.DECRYPT_MODE, r1.data, 0, 16);
        // Build AuthSecond with a CORRUPTED RndB — cryptogram will not verify.
        byte[] payload = new byte[32];
        System.arraycopy(rndA, 0, payload, 0, 16);
        byte[] bad = Ev2Client.rotRight(rndB);
        bad[0] ^= 0x01;
        System.arraycopy(bad, 0, payload, 16, 16);
        byte[] enc = Ev2Client.cbc(ZEROS, javax.crypto.Cipher.ENCRYPT_MODE, new byte[16], payload);
        Ev2Client.Response r2 = Ev2Client.transmit(this, (byte) 0xAF, enc);
        assertEquals(0x91AE, r2.sw, "wrong-key AuthSecond must answer 91AE (was ISO 6982 pre-fix)");
    }

    /**
     * Plain free-access rule: authenticated session + free rights still uses
     * plain framing for the command (quote: NTA_SESSION in CommModeHelper).
     */
    @Test
    void freeRightsKeepPlainFramingInSession() throws Exception {
        authZeros();
        assertEquals(0x9100, plainRead(), "plain read inside session must be accepted");
    }

    /**
     * Chained GetVersion: intermediate frames plain, final frame carries the
     * cumulative MACt (quote: NTA_CHANNEL in NxpConfigHandler). Pre-fix every
     * frame was MAC'd.
     */
    @Test
    void getVersionChainPlacesMactOnFinalFrameOnly() throws Exception {
        authZeros();
        // drive the 3-frame chain with the session active
        Ev2Client.Response f1 = Ev2Client.transmit(this, (byte) 0x60, new byte[0]);
        assertEquals(0x91AF, f1.sw, "frame 1 status");
        assertEquals(7, f1.data.length, "intermediate frame carries NO MACt (plain)");
        Ev2Client.Response f2 = Ev2Client.transmit(this, (byte) 0xAF, new byte[0]);
        assertEquals(0x91AF, f2.sw, "frame 2 status");
        assertEquals(7, f2.data.length, "intermediate frame carries NO MACt (plain)");
        Ev2Client.Response f3 = Ev2Client.transmit(this, (byte) 0xAF, new byte[0]);
        assertEquals(0x9100, f3.sw, "final frame status");
        // final frame: production info (7) + MACt(8) with the session active
        assertEquals(36, f3.data.length, "final frame = production(28) + MACt(8)");
        // chained-cmd MACt uses the CURRENT counter (no per-frame advance)
        byte[] data = java.util.Arrays.copyOf(f3.data, f3.data.length - 8);
        byte[] got = java.util.Arrays.copyOfRange(f3.data, f3.data.length - 8, f3.data.length);
        byte[] input = new byte[1 + 2 + 4 + data.length];
        input[0] = 0x00;
        input[1] = (byte) (ev2.ctr & 0xFF);
        input[2] = (byte) ((ev2.ctr >> 8) & 0xFF);
        System.arraycopy(ev2.ti, 0, input, 3, 4);
        System.arraycopy(data, 0, input, 7, data.length);
        byte[] expect = TestCrypto.cmac8Pub(ev2.sesMac, input);
        assertTrue(java.util.Arrays.equals(expect, got), "final-frame cumulative MACt verifies");
    }
}
