#!/usr/bin/env python3
"""auth_delay_test.py — deliberately trigger and recover from auth delay.

SAFETY:
- Card must be BLANK (factory K0 = zeros, KNOWN to us)
- Hard limit: 55 wrong attempts (50 to trigger + 5 buffer)
- TotFailCtr impact: ~55 (lifetime total ~130/1000 — 13%, safe)
- Recovery: rapid AuthFirst with correct key in the SAME connection
- Card is burn-allowed (04C474FA967380) — worst case: wipe cycle

Records the EXACT failure count that triggers 91AD, the delay-clearing
behavior, and the full recovery path on wire.
"""
import sys
import time
from smartcard.scard import *

READER = None
H = None
PROTO = None
MAX_WRONG = 55  # hard safety limit


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


def tx(apdu):
    rc, resp = SCardTransmit(H, PROTO, apdu)
    if rc:
        return "TXERR", b""
    sw = f"{resp[-2]:02X}{resp[-1]:02X}"
    data = bytes(resp[:-2])
    return sw, data


def select():
    return tx([0x00, 0xA4, 0x04, 0x00, 0x07,
               0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00])


def wrong_auth():
    """One complete wrong-key auth attempt: AuthFirst + garbage AuthSecond.
    Returns the AuthSecond SW (91AE = rejected, 91AD = delay)."""
    sw1, rnd_b_enc = tx([0x90, 0x71, 0x00, 0x00, 0x05,
                         0x00, 0x03, 0x00, 0x00, 0x00, 0x00])
    if sw1 != "91AF":
        return sw1, f"authfirst={sw1}"
    # AuthSecond with garbage cryptogram (wrong key)
    sw2, _ = tx([0x90, 0xAF, 0x00, 0x00, 0x20] + [0xEE] * 32 + [0x00])
    return sw2, ""


def main():
    ctx = find_and_connect()
    Y, G, R, B = "\033[33m", "\033[32m", "\033[31m", "\033[0m"

    # verify card is blank (sanity)
    sw_sel, _ = select()
    # complete the 3-frame GetVersion chain (else the card stays in
    # "additional frame" state and rejects non-0xAF commands with 91CA)
    sw_gv, _ = tx([0x90, 0x60, 0x00, 0x00, 0x00])
    if sw_gv == "91AF":
        tx([0x90, 0xAF, 0x00, 0x00, 0x00])  # frame 2
        tx([0x90, 0xAF, 0x00, 0x00, 0x00])  # frame 3 (final)
    print(f"{G}sanity: select={sw_sel} getver={sw_gv} chain=complete (card alive){B}")
    if sw_sel != "9000":
        print(f"{R}FAIL: card not selectable — aborting{B}")
        return 1

    # Phase 1: drive SeqFailCtr to threshold
    print(f"\n{Y}=== Phase 1: wrong-key attempts (hard limit {MAX_WRONG}) ==={B}")
    delay_at = None
    for i in range(1, MAX_WRONG + 1):
        sw, note = wrong_auth()
        marker = ""
        if sw == "91AD":
            delay_at = i
            marker = f" {R}<<< AUTH DELAY TRIGGERED{B}"
        elif sw == "91AE":
            marker = ""
        else:
            marker = f" {R}UNEXPECTED: {sw} {note} — stopping{B}"
            print(f"  attempt {i:>3}: {sw} {note}{marker}")
            break
        if i <= 3 or i % 10 == 0 or delay_at == i:
            print(f"  attempt {i:>3}: {sw}{marker}")
        if delay_at:
            break
        time.sleep(0.05)  # slight pacing, not too fast

    if not delay_at:
        print(f"\n{Y}Delay not triggered within {MAX_WRONG} attempts "
              f"(threshold may be higher than 50 for this state){B}")
        # still try recovery — the counter is elevated
        delay_at = MAX_WRONG

    # Phase 2: recovery — rapid correct AuthFirst in same connection
    print(f"\n{Y}=== Phase 2: recovery (rapid AuthFirst, same connection) ==={B}")
    recovered = False
    for j in range(1, 21):
        sw, data = tx([0x90, 0x71, 0x00, 0x00, 0x05,
                       0x00, 0x03, 0x00, 0x00, 0x00, 0x00])
        if sw == "91AF":
            print(f"  retry {j:>3}: {sw} + {len(data)}B RndB "
                  f"{G}<<< DELAY SPENT — CARD ACCEPTING{B}")
            recovered = True
            break
        elif sw == "91AD":
            if j <= 3 or j % 5 == 0:
                print(f"  retry {j:>3}: {sw} (delay active)")
        else:
            print(f"  retry {j:>3}: {sw} {R}UNEXPECTED{B}")
            break

    if not recovered:
        print(f"\n{R}RECOVERY FAILED — card may need different approach{B}")
        # emergency: try a full connect+select cycle
        print("  attempting reconnect + select...")
        SCardEndTransaction(H, SCARD_LEAVE_CARD)
        SCardDisconnect(H, SCARD_LEAVE_CARD)
        ctx2 = find_and_connect()
        sw_sel, _ = select()
        sw2, _ = tx([0x90, 0x71, 0x00, 0x00, 0x05,
                     0x00, 0x03, 0x00, 0x00, 0x00, 0x00])
        print(f"  reconnect: select={sw_sel} authfirst={sw2}")
        if sw2 == "91AF":
            recovered = True

    # Phase 3: verify card is fully healthy
    print(f"\n{Y}=== Phase 3: health check ==={B}")
    sw_gv, gv = tx([0x90, 0x60, 0x00, 0x00, 0x00])
    if sw_gv == "91AF":
        tx([0x90, 0xAF, 0x00, 0x00, 0x00])
        tx([0x90, 0xAF, 0x00, 0x00, 0x00])
    sw_fs, fs = tx([0x90, 0xF5, 0x00, 0x00, 0x01, 0x02, 0x00])
    print(f"  GetVersion: {sw_gv} ({len(gv)}B)")
    print(f"  GetFileSettings: {sw_fs} ({len(fs)}B)")
    verdict = "RECOVERED" if recovered else "STILL IN DELAY"
    color = G if recovered else R
    print(f"\n{color}=== RESULT: {verdict} | delay triggered at attempt "
          f"{delay_at} | recovered in {j} retries ==={B}")

    SCardEndTransaction(H, SCARD_LEAVE_CARD)
    SCardDisconnect(H, SCARD_LEAVE_CARD)
    return 0 if recovered else 1


if __name__ == "__main__":
    sys.exit(main())
