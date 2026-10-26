package com.ntag424;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/** jcardsim test rig: install the applet in-JVM and drive it with APDUs. */
public class AppletTestBase {
    protected static final byte[] NXP_AID = TestCrypto.hexBytes("D2760000850101");

    protected JavaxSmartCardInterface sim;

    protected void installApplet(byte[] uid) throws Exception {
        TestCrypto.selfTest();
        sim = new JavaxSmartCardInterface();
        byte[] b = new byte[1 + NXP_AID.length + 1 + 1 + uid.length];
        int p = 0;
        b[p++] = (byte) NXP_AID.length;
        System.arraycopy(NXP_AID, 0, b, p, NXP_AID.length);
        p += NXP_AID.length;
        b[p++] = 0;
        b[p++] = (byte) uid.length;
        System.arraycopy(uid, 0, b, p, uid.length);
        AID aid = new AID(NXP_AID, (short) 0, (byte) NXP_AID.length);
        sim.installApplet(aid, Ntag424Applet.class, b, (short) 0, (byte) b.length);
        ResponseAPDU r = selectNxp();
        if (r.getSW() != 0x9000) throw new AssertionError("SELECT failed");
    }

    protected ResponseAPDU transmit(byte[] apdu) {
        CommandAPDU c = new CommandAPDU(apdu);
        ResponseAPDU r = sim.transmitCommand(c);
        System.out.println("  >> " + TestCrypto.hex(apdu));
        System.out.println("  << " + TestCrypto.hex(r.getBytes()));
        return r;
    }

    protected ResponseAPDU selectNxp() {
        // jcardsim 2.2.2 does not auto-dispatch SELECT APDUs — the runtime
        // requires selectApplet() first (same lesson as the vpcd bridge).
        AID aid = new AID(NXP_AID, (short) 0, (byte) NXP_AID.length);
        if (!sim.selectApplet(aid)) throw new AssertionError("selectApplet failed");
        byte[] a = new byte[5 + NXP_AID.length];
        a[1] = (byte) 0xA4; a[2] = 0x04; a[3] = 0x00; a[4] = (byte) NXP_AID.length;
        System.arraycopy(NXP_AID, 0, a, 5, NXP_AID.length);
        return transmit(a);
    }

    protected ResponseAPDU cmd(byte cla, byte ins, byte p1, byte p2, byte[] data) {
        byte[] a = new byte[5 + (data == null ? 0 : data.length)];
        a[0] = cla; a[1] = ins; a[2] = p1; a[3] = p2;
        a[4] = (byte) (data == null ? 0 : data.length);
        if (data != null) System.arraycopy(data, 0, a, 5, data.length);
        return transmit(a);
    }
}
