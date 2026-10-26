# Spec audit & test methodology (Amperstrand fork)

This fork carries the upstream applet plus a three-part conformance
program built after the 2026-10 EV2 counter-bug hunt (see
`amperstrand/ev2-conformance-fixes`): spec quotes, unit regressions, and
a virtual-first E2E ladder.

## Layout

| Piece | Where | Runs on |
|---|---|---|
| Spec-quote drift config | `specquotes.toml` | any host |
| Quote annotations | `src/main/java/com/ntag424/**.java` (`// BOLT_SPEC:` / `// NTA_*:`) | — |
| EV2 conformance unit suite | `src/test/java/com/ntag424/` + `run-tests.sh` | JVM only (jcardsim) |
| CI | `.github/workflows/spec-audit.yml` | GitHub |

## Spec sources (pinned, never floating-HEAD)

- `boltcard/docs/{SPEC,DETERMINISTIC,CARD_PRIVACY}.md` — bolt-card
  service rules (markers `BOLT_SPEC`, `BOLT_DET`, `BOLT_PRIV`).
- `Amperstrand/ntag424 @ 7927c40` — the silicon-validated Rust host
  implementation the fixes were A/B-tested against. NXP's NTAG424
  datasheet and AN12196 are proprietary PDFs without canonical text
  (same policy as bolty-rs), so the wire layer is quote-locked to this
  crate's rule text instead (markers `NTA_SESSION`, `NTA_COUNTER`,
  `NTA_TESTS`, `NTA_CHANNEL`, `NTA_KEY`, `NTA_CFS`). Bumping the pin is
  a deliberate reviewed change that re-verifies every quote.

## Quote rules (same traps as bolty-rs)

- Verbatim text including backticks; quote starts ON the marker line.
- Consecutive `//` lines join into one multi-line quote — blank line
  between quote blocks and prose.
- One KNOWN DIVERGENCE is annotated in-source (ReadData `length = 0`
  returns empty instead of the remaining bytes, NT4H2421Gx 10.8.1).

## Unit suite

`./run-tests.sh` — no hardware, no pcscd: the applet runs in jcardsim
in-JVM. The test crypto is an independent AES-CMAC validated against
RFC 4493, plus a minimal EV2 client mirroring the wire layout the host
stack uses (including the CMt truncation convention: odd-index bytes).
Every test pins a behavior that was broken upstream:

| Test | Pins |
|---|---|
| `plainExchangeAdvancesCommandCounter` | the CmdCtr plain-exchange lockstep (the original A/B probe) |
| `wrongKeyAuthSecondAnswersNtagStatus` | 91AE (upstream answered ISO 6982) |
| `getVersionChainPlacesMactOnFinalFrameOnly` | chained-GetVersion MACt placement |
| `freeRightsKeepPlainFramingInSession` | free-access plain framing inside a session |
| `authRoundTripSucceedsWithFactoryKey` | EV2 AES auth roundtrip |

Negative control: `git checkout c75e320 -- src/main/java && ./run-tests.sh`
fails exactly the three fixed behaviors.

## E2E ladder (virtual first, card wear last)

1. **Virtual (free, fast)**: unit suite above; plus full-lifecycle runs
   through the vpcd bridge + the bolty-rs harness (see the H1 evidence
   bank: NtagBridge exposes the applet as a pcscd reader).
2. **Physical J3R180**: bolty harness against the real card via the
   ACR1252 (needs the applet installed — GP keys required).
3. **Real NTAG424 silicon**: gold-standard regression target; the host
   side is already silicon-validated by the crate's captured vectors.
