# ntag424-applet

JavaCard applet that emulates [NTAG 424 DNA](https://www.nxp.com/products/rfid-nfc/nfc-hf/ntag/ntag-424-dna:NTAG424DNA) — Type 4 NDEF, NXP `90` commands, EV2/LRP auth, SDM.

## Requirements

- JDK 17 (`JAVA_HOME` set)
- [Apache Ant](https://ant.apache.org/)
- [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro) (`gp`) for install

## Build

```bash
git clone --recursive <repo-url>
cd ntag424-applet
ant build
```

Output: `build/javacard/ntag424-applet.cap`

First `ant build` also compiles [ant-javacard](https://github.com/martinpaljak/ant-javacard) and pulls JavaCard SDKs (nested submodule).

## Install

| | AID |
|---|-----|
| Package | `D2760000850101` |
| Applet | `D276000085010101` |

```bash
gp --install build/javacard/ntag424-applet.cap \
   --create D276000085010101 \
   --default-contactless \
   --params <hex>
```

## Install parameters (`--params`)

Install data is a GP **C9** TLV: `C9` + length byte + payload.

Payload layout (what the applet reads):

| Offset | Length | Field |
|--------|--------|--------|
| 0 | 7 B | UID (14 hex chars) |
| 7 | 56 B | Read_Sig blob (112 hex chars), optional |

**UID only** (7 bytes → `07`):

```text
C907<uid_hex>
```

Example (synthetic UID — replace with yours):

```bash
gp --install build/javacard/ntag424-applet.cap \
   --create D276000085010101 \
   --default-contactless \
   --params C907AABBCCDDEEFF00
```

**UID + Read_Sig** (63 bytes → `3F`):

```text
C93F<uid_hex><read_sig_hex>
```

Example (format only — use values from your tag):

```bash
gp --install ... --params C93FAABBCCDDEEFF00<112_hex_chars_from_Read_Sig>
```

(`read_sig_hex` is 112 characters / 56 bytes from a real tag’s `Read_Sig` response.)

If `--params` is omitted or shorter than 63 bytes, the applet uses UID `00000000000000` and a built-in placeholder Read_Sig (fine for dev; not for cloning a specific tag).

`GetVersion` frame 3 returns the stored UID in the production-info block. Random ID (PICC) XOR salt is derived from the UID at install.

## After install

Factory Key 0 is all zeros. Authenticate, then personalize NDEF/SDM (file settings, URL mirrors, key change) with your own scripts.

`SetCardUid` (`0x52`) can change the UID after install when authenticated; normally set it via `--params` at install time.

## License

See [LICENSE](LICENSE).
