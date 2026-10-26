#!/usr/bin/env python3
"""negative_battery.py — bounded negative/robustness battery on NTAG424.

Working pattern (established by manual test): T1 connect +
SCardBeginTransaction holds the NXP application layer open.
"""
import sys
from smartcard.scard import *

READER = None
H = None
PROTO = None


def find_and_connect():
    global READER, H, PROTO
    rc, ctx = SCardEstablishContext(SCARD_SCOPE_USER)
    rc, rs = SCardListReaders(ctx, [])
    for r in rs:
        if "ACR1252" in r and "PICC" in r:
            READER = r
    if not READER:
        raise SystemExit("no ACR1252 PICC reader")
    rc, h, proto = SCardConnect(ctx, READER, SCARD_SHARE_SHARED,
                                SCARD_PROTOCOL_T1)
    if rc:
        raise SystemExit(f"connect: {SCardGetErrorMessage(rc)}")
    rc_bt = SCardBeginTransaction(h)
    if rc_bt:
        raise SystemExit(f"begin-tx: {SCardGetErrorMessage(rc_bt)}")
    H, PROTO = h, proto
    return ctx


def tx(apdu, label, expect=""):
    rc, resp = SCardTransmit(H, PROTO, apdu)
    if rc:
        print(f"[{label}] TX-ERROR {SCardGetErrorMessage(rc)} {expect}")
        return None
    sw = f"{resp[-2]:02X}{resp[-1]:02X}"
    data = bytes(resp[:-2]).hex().upper()
    print(f"[{label}] SW={sw} data={data[:40]}{'…' if len(data) > 40 else ''} {expect}")
    return sw


def resel():
    return tx([0x00, 0xA4, 0x04, 0x00, 0x07,
               0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00], "resel")


def main():
    ctx = find_and_connect()
    Y, B = "\033[33m", "\033[0m"
    print(f"{Y}=== NEGATIVE BATTERY on real NTAG424 (all recoverable) ==={B}")

    tx([0x00, 0xA4, 0x04, 0x00, 0x07,
        0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00], "select")
    tx([0x90, 0x60, 0x00, 0x00, 0x00], "sanity-getver", "(expect 91AF)")

    # 1. wrong-key ladder: 5 consecutive full AuthFirst with WRONG LenCap key data
    print(f"\n{Y}--- 1. wrong-key AuthFirst ladder (5x, budget 5/50) ---{B}")
    for i in range(1, 6):
        # AuthFirst with valid format but the card will reject AuthSecond
        # (garbage cryptogram) — this is the 91AE path
        rc1 = tx([0x90, 0x71, 0x00, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00],
                 f"ladder-{i}-authfirst")
        if rc1 == "91AF":
            # got RndB; send garbage AuthSecond = wrong-key rejection
            tx([0x90, 0xAF, 0x00, 0x00, 0x20] + [0xBB] * 32 + [0x00],
               f"ladder-{i}-authsecond", "(expect 91AE)")
    # recovery: correct AuthFirst (factory zeros) still gets 91AF
    tx([0x90, 0x71, 0x00, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00],
       "recovery-authfirst", "(expect 91AF — SeqFailCtr reset by design)")

    # 2. invalid key number
    print(f"\n{Y}--- 2. AuthFirst with invalid key number K7 ---{B}")
    tx([0x90, 0x71, 0x00, 0x00, 0x05, 0x07, 0x03, 0x00, 0x00, 0x00, 0x00],
       "authfirst-key7", "(expect 919D/parameter or 6982)")

    # 3. truncated AuthFirst
    print(f"\n{Y}--- 3. truncated AuthFirst (Lc=3 but claims 5) ---{B}")
    tx([0x90, 0x71, 0x00, 0x00, 0x03, 0x00, 0x03, 0x00],
       "authfirst-truncated", "(expect 9103 length)")

    # 4. unknown INS in NXP CLA
    print(f"\n{Y}--- 4. unknown INS 0x77 in CLA 0x90 ---{B}")
    tx([0x90, 0x77, 0x00, 0x00, 0x00], "np-cla-unknown-ins", "(expect 91 7E?)")

    # 5. NXP INS with ISO CLA
    print(f"\n{Y}--- 5. NTAG INS (F5) with ISO CLA 0x00 ---{B}")
    tx([0x00, 0xF5, 0x00, 0x00, 0x01, 0x02], "ntag-ins-iso-cla", "(expect 6D00)")

    # 6. SetCardUid (applet-only)
    print(f"\n{Y}--- 6. SetCardUid INS 0x52 (applet-only A/B marker) ---{B}")
    tx([0x90, 0x52, 0x00, 0x00, 0x07, 0x04, 0x33, 0x7D, 0x8A, 0xAE, 0x17, 0x90, 0x00],
       "setcarduid-silicon", "(expect 6D00 or 917E)")

    # 7. ReadData beyond EOF (unauthenticated, file 02, huge offset)
    print(f"\n{Y}--- 7. ReadData beyond file size ---{B}")
    resel()
    tx([0x90, 0xAD, 0x00, 0x00, 0x07, 0x02, 0x01, 0xFF, 0xF0, 0x00, 0x00, 0x10, 0x00],
       "readdata-beyond-eof", "(expect 9103)")

    # 8. GetFileSettings on non-existent file
    print(f"\n{Y}--- 8. GetFileSettings on file 0x07 ---{B}")
    tx([0x90, 0xF5, 0x00, 0x00, 0x01, 0x07, 0x00], "getfs-file7", "(expect 927E/file-not-found)")

    # 9. ISO write to CC file (read-only)
    print(f"\n{Y}--- 9. ISO UpdateBinary on CC file E103 ---{B}")
    tx([0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x03], "select-cc")
    tx([0x00, 0xD6, 0x00, 0x00, 0x02, 0x00, 0x0F], "write-cc", "(expect 6982)")
    resel()

    # 10. AuthSecond without prior AuthFirst
    print(f"\n{Y}--- 10. AuthSecond cold (no AuthFirst) ---{B}")
    tx([0x90, 0xAF, 0x00, 0x00, 0x20] + [0x55] * 32 + [0x00],
       "authsecond-cold", "(expect 6982 or 9103)")

    print(f"\n{Y}=== complete ==={B}")
    SCardEndTransaction(H, SCARD_LEAVE_CARD)
    SCardDisconnect(H, SCARD_LEAVE_CARD)


if __name__ == "__main__":
    main()
