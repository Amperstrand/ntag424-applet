package com.ntag424;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Minimal host-side EV2 AES client for tests. Mirrors the wire layout the
 * applet implements (validated end-to-end against the silicon-strict
 * ntag424 crate host stack); the CMAC primitive is independent and
 * RFC 4493-verified (see TestCrypto.selfTest).
 */
public final class Ev2Client {
    public final byte[] ti = new byte[4];
    public final byte[] sesEnc = new byte[16];
    public final byte[] sesMac = new byte[16];
    public int ctr;
    public boolean active;

    private static final byte[] ENC_PURPOSE = {(byte) 0xA5, 0x5A};
    private static final byte[] MAC_PURPOSE = {0x5A, (byte) 0xA5};
    private static final byte[] ENC_IV_PREFIX = {(byte) 0xA5, 0x5A};
    private static final byte[] DEC_IV_PREFIX = {0x5A, (byte) 0xA5};

    /** AuthenticateEV2First+Second with the given key. Returns the TI. */
    public void authenticate(AppletTestBase rig, byte keyNo, byte[] key) throws Exception {
        byte[] rndA = new byte[16];
        new java.security.SecureRandom().nextBytes(rndA);

        // Part 1: keyNo, LenCap=03, PCDcap2=000000
        Response r = transmit(rig, (byte) 0x71, new byte[]{keyNo, 0x03, 0, 0, 0});
        if (r.sw != 0x91AF) throw new AssertionError("AuthFirst SW=" + Integer.toHexString(r.sw));
        byte[] rndB = aesEcb(key, Cipher.DECRYPT_MODE, r.data, 0, 16);

        // Session keys (SV layout per the applet's fillSessionVector)
        System.arraycopy(cmac(key, sv(ENC_PURPOSE, rndA, rndB)), 0, sesEnc, 0, 16);
        System.arraycopy(cmac(key, sv(MAC_PURPOSE, rndA, rndB)), 0, sesMac, 0, 16);

        // Part 2: CBC(K0, RndA || rotRight(RndB)) — no trailing MAC1 in this profile
        byte[] payload = new byte[32];
        System.arraycopy(rndA, 0, payload, 0, 16);
        System.arraycopy(rotLeft(rndB), 0, payload, 16, 16); // applet checks rotRight(recv)==RndB
        byte[] enc = cbc(key, Cipher.ENCRYPT_MODE, new byte[16], payload);
        Response r2 = transmit(rig, (byte) 0xAF, enc);
        if (r2.sw != 0x9100) throw new AssertionError("AuthSecond SW=" + Integer.toHexString(r2.sw));

        // Response: CBC(K0, TI || rotLeft(RndA) || zeros12)
        byte[] resp = cbc(key, Cipher.DECRYPT_MODE, new byte[16], r2.data);
        System.arraycopy(resp, 0, ti, 0, 4);
        ctr = 0;
        active = true;
    }

    /** Build a MACt-protected command body: header||data||MACt. */
    public byte[] macCommand(byte cmd, byte[] header, byte[] data) throws Exception {
        byte[] input = new byte[1 + 2 + 4 + header.length + (data == null ? 0 : data.length)];
        int p = 0;
        input[p++] = cmd;
        input[p++] = (byte) (ctr & 0xFF);
        input[p++] = (byte) ((ctr >> 8) & 0xFF);
        System.arraycopy(ti, 0, input, p, 4); p += 4;
        System.arraycopy(header, 0, input, p, header.length);
        if (data != null) System.arraycopy(data, 0, input, p + header.length, data.length);
        byte[] mac = cmac8(sesMac, input);
        byte[] out = new byte[header.length + (data == null ? 0 : data.length) + 8];
        System.arraycopy(header, 0, out, 0, header.length);
        if (data != null) System.arraycopy(data, 0, out, header.length, data.length);
        System.arraycopy(mac, 0, out, out.length - 8, 8);
        return out;
    }

    /**
     * Verify a MACt'd response: MAC over status||ctr+1||TI||data, where the
     * counter is the POST-command-increment value (silicon semantics).
     * Advances the local counter by one on success.
     */
    public boolean verifyResponse(byte status, byte[] body) throws Exception {
        int next = ctr + 1;
        byte[] data = body == null ? new byte[0]
                : java.util.Arrays.copyOf(body, body.length - 8); // strip MACt
        byte[] input = new byte[1 + 2 + 4 + data.length];
        int p = 0;
        input[p++] = status;
        input[p++] = (byte) (next & 0xFF);
        input[p++] = (byte) ((next >> 8) & 0xFF);
        System.arraycopy(ti, 0, input, p, 4);
        System.arraycopy(data, 0, input, p + 4, data.length);
        byte[] expect = cmac8(sesMac, input);
        if (body == null || body.length < 8) return false;
        byte[] got = new byte[8];
        System.arraycopy(body, body.length - 8, got, 0, 8);
        boolean ok = java.util.Arrays.equals(expect, got);
        if (ok) ctr++;
        return ok;
    }

    /** The counter the applet expects for the NEXT command (post plain op). */
    public void advance() { ctr++; }

    private static byte[] sv(byte[] purpose, byte[] rndA, byte[] rndB) {
        byte[] sv = new byte[32];
        sv[0] = purpose[0]; sv[1] = purpose[1];
        sv[2] = 0x00; sv[3] = 0x01; sv[4] = 0x00; sv[5] = (byte) 0x80;
        sv[6] = rndA[0]; sv[7] = rndA[1];
        for (int i = 0; i < 6; i++) sv[8 + i] = (byte) (rndA[2 + i] ^ rndB[i]);
        System.arraycopy(rndB, 6, sv, 14, 10);
        System.arraycopy(rndA, 8, sv, 24, 8);
        return sv;
    }

    static byte[] rotRight(byte[] b) {
        byte[] o = new byte[16];
        o[0] = b[15];
        System.arraycopy(b, 0, o, 1, 15);
        return o;
    }

    static byte[] rotLeft(byte[] b) {
        byte[] o = new byte[16];
        System.arraycopy(b, 1, o, 0, 15);
        o[15] = b[0];
        return o;
    }



    /** Continue an in-progress auth given the AuthFirst response
     *  (extracted from SiliconParityTest's step executor). */
    public Response continueAuthCapture(AppletTestBase rig, Response af) throws Exception {
        Response out = _continueAuth(rig, af);
        return out;
    }

    public void continueAuth(AppletTestBase rig, Response af) throws Exception {
        _continueAuth(rig, af);
    }

    private Response _continueAuth(AppletTestBase rig, Response af) throws Exception {
        byte[] rndA = new byte[16];
        new java.security.SecureRandom().nextBytes(rndA);
        byte[] rndB = aesEcb(new byte[16], Cipher.DECRYPT_MODE, af.data, 0, 16);
        System.arraycopy(cmac(new byte[16], sv(ENC_PURPOSE, rndA, rndB)), 0, sesEnc, 0, 16);
        System.arraycopy(cmac(new byte[16], sv(MAC_PURPOSE, rndA, rndB)), 0, sesMac, 0, 16);
        byte[] payload = new byte[32];
        System.arraycopy(rndA, 0, payload, 0, 16);
        System.arraycopy(rotLeft(rndB), 0, payload, 16, 16);
        byte[] enc = cbc(new byte[16], Cipher.ENCRYPT_MODE, new byte[16], payload);
        Response r2 = transmit(rig, (byte) 0xAF, enc);
        if (r2.sw != 0x9100) throw new AssertionError("AuthSecond " + Integer.toHexString(r2.sw));
        byte[] resp = cbc(new byte[16], Cipher.DECRYPT_MODE, new byte[16], r2.data);
        System.arraycopy(resp, 0, ti, 0, 4);
        ctr = 0;
        active = true;
        this.rndALast = rndA;
        return r2;
    }

    private byte[] rndALast;

    // --- session-encrypted commands (5F etc.) --------------------------------

    /** Encrypt a command payload: ISO-9797-1 M2 pad + CBC(sesEnc, derived IV).
     *  Mirrors the applet's decryptCommandData (prefix 5A A5). */
    public byte[] encryptCommand(byte[] plaintext) throws Exception {
        // empirically pinned (SdmDebug sweep): command-data IV uses the
        // A5 5A prefix with the CURRENT counter (before this command's MAC)
        byte[] iv = sessionIv(ENC_IV_PREFIX);
        int padLen = ((plaintext.length / 16) + 1) * 16;
        byte[] padded = new byte[padLen];
        System.arraycopy(plaintext, 0, padded, 0, plaintext.length);
        padded[plaintext.length] = (byte) 0x80;
        return cbc(sesEnc, Cipher.ENCRYPT_MODE, iv, padded);
    }

    /** CBC IV = AES(sesEnc, prefix2 || TI(4) || ctrLE2 || zeros6). */
    private byte[] sessionIv(byte[] prefix) throws Exception {
        byte[] ivIn = new byte[16];
        ivIn[0] = prefix[0]; ivIn[1] = prefix[1];
        System.arraycopy(ti, 0, ivIn, 2, 4);
        ivIn[6] = (byte) (ctr & 0xFF);
        ivIn[7] = (byte) ((ctr >> 8) & 0xFF);
        return aesEcb(sesEnc, Cipher.ENCRYPT_MODE, ivIn, 0, 16);
    }

    /**
     * MAC'd + encrypted ChangeFileSettings (INS 5F). Plaintext =
     * options(1) || rights(2) || [SDM block]. Returns sw; verifies the
     * MACt response when present.
     */
    public int changeFileSettings(AppletTestBase rig, byte fileNo, byte[] plaintext) throws Exception {
        byte[] enc = encryptCommand(plaintext);
        byte[] body = macCommand((byte) 0x5F, new byte[]{fileNo}, enc);
        Response r = transmit(rig, (byte) 0x5F, body);
        if (r.sw != 0x9100) return r.sw;
        // command MAC consumed a counter at verify; response MACt (Case-1
        // style, data=empty) is verified and advances again per applet flow:
        // applet advanced once at cmd verify; response MACt over next ctr.
        if (r.data.length >= 8) {
            if (!verifyResponse((byte) 0x00, r.data)) return 0x911E;
        } else {
            ctr++; // bare response: only the command-side advance happened
        }
        return r.sw;
    }

    // --- transport + crypto helpers ----------------------------------------
    public static class Response {
        public int sw;
        public byte[] data;
    }

    public static Response transmit(AppletTestBase rig, byte ins, byte[] data) {
        javax.smartcardio.ResponseAPDU r = rig.cmd((byte) 0x90, ins, (byte) 0x00, (byte) 0x00, data);
        Response out = new Response();
        out.sw = r.getSW();
        out.data = r.getData();
        return out;
    }

    static byte[] aesEcb(byte[] key, int mode, byte[] in, int off, int len) throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
        c.init(mode, new SecretKeySpec(key, "AES"));
        return c.doFinal(java.util.Arrays.copyOfRange(in, off, off + len));
    }

    static byte[] cbc(byte[] key, int mode, byte[] iv, byte[] in) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
        c.init(mode, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return c.doFinal(in);
    }

    static byte[] cmac(byte[] key, byte[] msg) throws Exception {
        java.lang.reflect.Method m = TestCrypto.class.getDeclaredMethod("cmac", byte[].class, byte[].class);
        m.setAccessible(true);
        return (byte[]) m.invoke(null, key, msg);
    }

    static byte[] cmac8(byte[] key, byte[] msg) throws Exception {
        java.lang.reflect.Method m = TestCrypto.class.getDeclaredMethod("cmac8", byte[].class, byte[].class);
        m.setAccessible(true);
        return (byte[]) m.invoke(null, key, msg);
    }
}
