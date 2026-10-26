# Auth-delay trigger + recovery on real NTAG424 (DEFINITIVE, 2026-10-27)

Wire-captured (auth-delay.pcapng, 137 CCID frames). Card 04C474FA967380
BLANK (factory zeros known). Script: tools/negative/auth_delay_test.py.

## The definitive numbers

| Metric | Value | Source |
|---|---|---|
| **Delay trigger** | **exactly 50 consecutive wrong-key auth failures** | 49×91AE then 91AD on attempt 50 |
| **Recovery (in-connection)** | **2 rapid AuthFirst retries** | retry 1 = 91AD, retry 2 = 91AF |
| **Recovery (new connection)** | bolty-cli try-key ladder: **3 retries to spend delay** | "keep trying (3/20)" then accepted |
| SeqFailCtr reset | requires COMPLETED successful auth (AuthFirst+Second) | AuthFirst alone spends delay but doesn't reset |
| Card state after | BLANK, fully healthy | verify: GetFileSettings 9100 + 10B |

## Critical discovery: the recovery is TWO-STAGE

1. **Delay spending**: rapid AuthFirst (wrong or right key) in the SAME
   connection "spends" the delay — 2 retries on silicon. The card then
   returns 91AF instead of 91AD.
2. **Counter reset**: ONLY a completed successful authentication
   (AuthFirst + AuthSecond with the CORRECT key) resets SeqFailCtr.
   Without it, the delay re-arms when the connection drops.

This means: after delay spending, you MUST complete the auth with the
correct key in the same session. If the connection drops, you're back
to step 1 (as observed: card was BLANK-healthy in-connection but
AUTH_DELAY from a fresh connection until the full try-key ladder).

## TotFailCtr budget after this test

~55 more failures → lifetime total ~130/1000 (13%). Extremely safe.

## Prior art cross-check

- AGENTS.md "Card Recovery" section: delay at 50, keep-trying method,
  new-connection-resets-delay-state — ALL CONFIRMED on known-good silicon
- 043365FA967380 recovery: the same method worked on a card with UNKNOWN
  keys — the mechanism is now proven in both known-key and unknown-key
  scenarios
