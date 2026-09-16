# XRPMAN // REKEY V8

A controlled XRPL account-recovery procedure, not a button that rekeys a wallet.

```
01 SCAN → 02 AUTHORITY → 03 NEW KEY → 04 REKEY → 05 VERIFY LEDGER
       → 06 PROVE CONTROL → 07 DISABLE MASTER → 08 FINAL AUDIT
```

**V8 never disables master authorisation because the previous transaction returned
`tesSUCCESS`.** Before step 07 unlocks, the new credential must have signed a transaction
that a validated ledger accepted. That single rule is what separates this from V7.

> V7 is preserved untouched on `main`. This is `v8-security-refresh` work.

---

## Why V8 exists

`docs/V7-AUDIT.md` is the full Phase 1 record. The three findings that forced a rebuild
rather than a patch:

| | Finding | Evidence |
|---|---|---|
| **F1** | V7's "Secret Numbers" backup is lossy — it packs a 24-bit value then emits `val % 1000000`, discarding the top four bits | **0 of 10,000** random round trips survived |
| **F2** | The generator and the loader used different entropy spaces (32-byte private key out, 24-byte `fromEntropy` in) | the generated address could never reload |
| **F3** | The "mnemonics" are not BIP39 — a **1902-word** list, a custom shift-xor checksum, and `wordList[idx % 1902]` | no BIP39 tool can read them, including V7 itself |
| **F5** | The replacement key was never exercised before the master key was destroyed | — |

Both regressions are pinned by tests, so the reasons stay provable.

---

## Run it

The app is ES modules, so it needs to be served rather than opened from `file://`:

```sh
python3 -m http.server 8080
# → http://127.0.0.1:8080
```

No build step, no bundler, no `npm install`. Everything needed is in the repo.

### Tests

```sh
node tests/run.js           # 56 unit and failure-path tests
node tests/integration.js   # 22-step offline drill against a mock rippled
```

The integration drill signs with real keys and decodes the resulting blobs, so the
regular-key authorisation in step 06 is verified cryptographically, not asserted.

---

## Layout

```
index.html              application shell, CSP, eight phase panels
src/app.js              wizard orchestration and the phase state machine
src/xrpl.js             ledger transport — every read pinned to a validated ledger
src/wallet.js           key parsing, derivation, generation, disposal
src/security.js         account scanner, flag decoding, gate engine
src/ui.js               HUD rendering (textContent only, never innerHTML)
styles/xrpman.css       ShadowWatch HUD
vendor/                 xrpl 5.2.0 browser bundle + provenance digests
tests/                  unit, failure-path and integration suites
docs/V7-AUDIT.md        Phase 1 audit record
```

---

## The phases

### 01 SCAN
Interrogates the ledger before offering any action: existence, balance, reserve and
spendable amount, master-key state, existing regular key, signer list, account flags,
sequence, and whether the endpoint actually serves the network you selected.

Entropy-based inputs (secret numbers, hex) do not encode which curve they belong to,
and xrpl.js changed its default from secp256k1 to ed25519 between 2.x and 5.x (audit
F14). V8 therefore derives **both** candidates and probes each against the ledger
instead of guessing:

```
rNiNSFyhVr5xfp8o8G5Ku81if8rdDrai5z   SECP256K1 · FUNDED · 25.000000 XRP
r4XTuAXLKfbKQZCqK7JXPGxi2eu9QdEd5g   ED25519   · NOT FOUND ON LEDGER
```

### 02–03 AUTHORITY / NEW KEY
Generate a fresh authority locally, or nominate an address you already control.
Generated credentials never leave the tab. Continuing requires retyping the new address —
a checkbox alone does not attest to a backup.

Secret numbers are emitted **only** for secp256k1, because the XRPL Secret Numbers
standard defines 16 bytes of family-seed entropy and a compliant restorer reads it as
secp256k1. Printing them beside an ed25519 seed would hand you a backup that restores a
different account.

### 04 REKEY
The account is re-scanned immediately before signing, then `SetRegularKey` is displayed
exactly as it will be submitted and signed with the master key.

### 05 VERIFY LEDGER
`account_info` is re-read at `ledger_index: 'validated'` and the transaction is
independently looked up by hash. `RegularKey !== expected` is a hard stop: step 06 stays
locked.

### 06 PROVE CONTROL
The step V7 had no equivalent of. A bare `AccountSet` — no flag set, no flag cleared, no
value moved — is signed by the **new** key and submitted. It costs a fee and one sequence
number, and it is the only thing that can answer the question that matters:

```
DERIVED ADDRESS     MATCH
REGULARKEY LEDGER   MATCH
SIGNATURE           VALID
TRANSACTION         VALIDATED

CONTROL PROVEN ✓
```

If you nominated an existing address at step 02, its secret is required here. Without it,
control cannot be proven and step 07 never unlocks. That is the intended behaviour.

### 07 DISABLE MASTER
Framed as what it is — disabling authorisation by the master key, not destroying a seed.
The account and its balance are untouched.

Six requirements, all evaluated against a freshly scanned ledger, plus an explicit
acknowledgement and a typed `DISABLE MASTER`. There is no override parameter and no
bypass button.

`asfDisableMaster` is signed with the **master** key, because rippled requires it —
a regular key attempting it gets `tecNEED_MASTER_KEY`. Both that and
`tecNO_ALTERNATIVE_KEY` are surfaced with an explanation rather than a raw code.

### 08 FINAL AUDIT
Re-queries the account and prints a report carrying every transaction hash for
independent explorer verification. It contains no private key material — a test asserts
that the report template cannot reference one.

---

## Security posture

**Secrets.** Memory only, for the lifetime of the tab. No `localStorage`, no
`sessionStorage`, no IndexedDB, no cookies, no URL parameters, no analytics, no logging of
key material, and no network request that carries a secret. A test walks `src/` and fails
the build if any of those APIs appear.

**Dependencies.** One, vendored in-tree: `xrpl@5.2.0`. Digests and a verification recipe
are in `vendor/README.md`. V7's `buffer` polyfill and its `bip39` web-worker bundle —
loaded as a classic script and referenced nowhere — are gone.

**CSP.** Declared before any script, so it governs them (V7's sat after its script tags):

```
default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:;
font-src 'self'; connect-src wss://<xrpl endpoints only>;
base-uri 'none'; form-action 'none'; object-src 'none';
```

No `unsafe-inline` for scripts or styles, and no third-party origin of any kind — the page
makes no outbound request other than the XRPL WebSocket. A test asserts that every endpoint
the code can reach is present in `connect-src`, so V7's testnet-blocking mismatch (F6)
cannot recur.

**Rendering.** Ledger data reaches the DOM through `textContent` only.

### Deployment

`frame-ancestors` is absent from the `<meta>` policy because browsers ignore it there — it
only works as a real header. `vercel.json` ships that header and the rest of the set:

```
Content-Security-Policy: frame-ancestors 'none'
X-Frame-Options: DENY
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Permissions-Policy: camera=(), geolocation=(), microphone=(), payment=(), usb=(), ...
```

A header CSP and the `<meta>` CSP both apply and a browser enforces their intersection, so
the header carries `frame-ancestors` alone and the page's own policy still governs
everything else. `Permissions-Policy` deliberately leaves clipboard access alone — step 08
copies the audit report.

Serving this anywhere other than Vercel means porting those headers to that host; the
`<meta>` policy alone does not cover framing.

---

## Mainnet gate

**Mainnet is locked in this build.** `MAINNET_ENABLED = false` in `src/xrpl.js`;
constructing a mainnet link throws `NETWORK_GATED`, and the toggle is disabled.

Working code is not the bar. The release sequence is:

```
V8 DEV → Testnet functional test → transaction audit → failure-path tests
       → mobile/browser tests → Testnet recovery drill → Mainnet-ready review
```

| Gate | State |
|---|---|
| Transaction audit | **Done** — bodies and signer identity verified by decoding real signed blobs |
| Failure-path tests | **Done** — 78 checks across both suites |
| Mobile / browser tests | **Done** — Chromium at 1280×900 and 393×851; no horizontal scroll, no tap target under 40px |
| Testnet functional test | **Outstanding** — requires live testnet access |
| Testnet recovery drill | **Outstanding** — restore from the emitted credentials on a fresh device |
| Mainnet-ready review | **Outstanding** |

Covered failure paths: wrong secret, wrong network, network-id mismatch, nonexistent
account, pre-existing regular key, already-disabled master, signer list present, malformed
address, regular key equal to the account, corrupted secret-number checksum, malformed
registry input, insufficient reserve, RPC unreachable, transaction rejection, stale ledger,
failed control proof, `tecNEED_MASTER_KEY`, `tecNO_ALTERNATIVE_KEY`, and double-submit.

Page refresh mid-procedure is a full reset by design — nothing persists — and an
`beforeunload` prompt guards against doing it by accident.

Do not flip `MAINNET_ENABLED` until the outstanding rows above are closed.

---

## Recovering from an interrupted run

Nothing is stored, so recovery is a matter of where the ledger stopped:

| Stopped after | State | What to do |
|---|---|---|
| 04, before 05 | RegularKey may or may not be set | Re-run 01; the scan reports the current regular key |
| 05 verified, before 06 | RegularKey set, master still active | Both keys work. Re-run and prove control before continuing |
| 06 proven, before 07 | Control proven, master still active | Both keys work. Re-run to reach 07 |
| 07 complete | Master disabled | The regular key is now the only authority — the one you proved at 06 |

Re-running step 04 when the ledger already carries the target regular key is detected and
skipped rather than resubmitted.
