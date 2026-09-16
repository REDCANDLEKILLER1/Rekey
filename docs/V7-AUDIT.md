# V7 SECURITY AUDIT — PHASE 1 RECORD

Audit target: `index.html` @ `main` (39,559 bytes, commit `c1a2f46`).
Audit date: 2026-09-16. Gate status: **PASSED — V8 may proceed.**

`main` is untouched. Every finding below is reproducible against the locked V7 checkpoint.

---

## 1. V7 FEATURE INVENTORY

| Step | Feature | Implementation |
|---|---|---|
| 0 | Splash gate | `completeStep(0)` |
| 1 | Network select | `setNet()` — **MAINNET is the default** |
| 2 | Load source wallet | JSON registry file / 8×6-digit "Secret Numbers" / seed-or-mnemonic text |
| 2 | Account probe | `account_info` → address + balance only |
| 3 | "Universal Safe Key" | `generateUniversalKey()` — address, seed, m12/m16/m24, 8 secret numbers, hex entropy, pubkey |
| 3 | Backup attestation | single checkbox `chk-saved` |
| 4 | Rekey | `SetRegularKey` → `submitAndWait` |
| 5 | Disable master | `AccountSet` `SetFlag: 4` (asfDisableMaster) |

Transaction construction traced:

```js
// step 4 — executeRekey()
{ TransactionType: "SetRegularKey", Account: activeWallet.address, RegularKey: newKey }
autofill → activeWallet.sign → submitAndWait(failHard:false)

// step 5 — disableMasterKey()
{ TransactionType: "AccountSet", Account: activeWallet.address, SetFlag: 4 }
autofill → activeWallet.sign → submitAndWait
```

Both transaction bodies are **correct XRPL**. `SetFlag: 4` is genuinely `asfDisableMaster`, and signing
step 5 with the master wallet is required by the protocol (`tecNEED_MASTER_KEY` otherwise). The transaction
layer is not where V7 fails.

---

## 2. CRITICAL FINDINGS

### F1 — "Secret Numbers" encoding is lossy. Round-trip success rate: 0%.

`entropyToSecretNumbers()` packs three bytes into a 24-bit integer (range `0..16777215`) and then emits
`String(val % 1000000)`. The decoder in `loadWallet()` inverts it as if no modulo happened:

```js
entropy[i*3] = (val >> 16) & 0xFF;   // val can only be 0..999999 → bits 20-23 are gone
```

Measured over 10,000 random 24-byte inputs:

```
V7 SecretNumber round-trip success: 0/10000 = 0.0000%
per-chunk survival probability:     1000000/16777216 = 0.059605
8 chunks:                           1.593e-10
```

Any wallet backed up using V7's secret numbers is **unrecoverable**. This is not a theoretical bound —
zero of ten thousand trials survived.

### F2 — The generator and the loader do not share an entropy space.

`generateUniversalKey()` takes `wallet.privateKey` (33-byte hex, `00`-prefixed → 32 bytes) as its entropy
source, then encodes only bytes `[0..23]` into secret numbers. `loadWallet()` rebuilds a 24-byte array and
calls `xrpl.Wallet.fromEntropy(entropy)`, whose contract is **16 bytes of entropy**, not 24, and not a
private key.

The generated address can never equal the reloaded address — independently of F1. The two code paths were
never round-trip tested against each other.

### F3 — The mnemonics are not BIP39.

`getWordList()` returns **1902 words, not 2048**. 146 words are absent; the list jumps `ozone → patient`,
dropping `pact, paddle, page, pair, palace, palm, panda, panel, panic, panther, paper, parade, parent,
park, parrot, party, pass, patch, path`.

Compounding it, `bytesToMnemonic()`:
- computes a **custom non-SHA256 checksum** (`simpleChecksum`, a 32-bit shift-xor);
- indexes with `wordList[idx % wordList.length]`, and `2048 % 1902 ≠ 0`, so the 11-bit→word mapping is
  neither injective nor bit-aligned.

`m12` / `m16` / `m24` are decorative strings. No BIP39 tool, hardware wallet, or `Wallet.fromMnemonic()`
can consume them. The reload path calls `xrpl.Wallet.fromMnemonic(secret)`, which expects real BIP39 —
so V7 cannot even read its own output.

**Conclusion for Phase 4 of the V8 plan:** the "Universal Safe Key" is a write-only format. It is retired,
on evidence rather than preference.

---

## 3. HIGH FINDINGS

### F4 — Master key is disabled on the strength of an in-memory boolean.

`disableMasterKey()` gates on `rekeyCompleted`, set by `executeRekey()` when the submit result reads
`tesSUCCESS`. The ledger is never re-queried. A `tesSUCCESS` on a transaction that was later reorganised
out, or a stale/lying node response, is sufficient to proceed to an irreversible operation.

### F5 — The replacement authority is never exercised before the master key is destroyed.

V7 never signs anything with the new regular key. It disables the only working credential on the account
while having no evidence the replacement can control it. This is the worst-case failure mode the V8 plan
exists to close.

### F6 — CSP blocks the testnet, and does not govern the scripts it lists.

```
connect-src 'self' wss://*.ripple.com wss://xrplcluster.com wss://xrpl.ws;
```

`NETS.test` is `wss://s.altnet.rippletest.net:51233`, which matches none of these. Under an enforcing
browser, testnet is unreachable — pushing operators onto mainnet, which is already the default (F10).

Separately, the CSP `<meta>` sits at line 24, **after** the `<script src>` tags at lines 9–18. A meta
policy applies only from the point it is parsed, so the three CDN scripts it nominally authorises load
outside of it entirely.

---

## 4. MEDIUM / LOW FINDINGS

| ID | Severity | Finding |
|---|---|---|
| F7 | MEDIUM | **Zero SRI.** `grep -c 'integrity='` → `0`. Three CDN scripts, wallet-grade blast radius, no pinning beyond the version in the URL. |
| F8 | MEDIUM | `xrpl@2.14.0` is obsolete (current: 5.2.0). `Wallet.fromMnemonic` now requires an explicit `mnemonicEncoding` option. |
| F9 | MEDIUM | `bip39@3.1.0/util/bundle.worker.min.js` is a **web-worker bundle loaded as a classic script**. Wrong artifact; contributes nothing; `bip39` is never referenced in V7 code. |
| F10 | MEDIUM | `currentNet = 'main'` — mainnet is the default network on a tool whose failure mode is permanent account loss. |
| F11 | LOW | Secrets are written to the DOM (`target-s`, `target-m*`, `target-hex`) and to the clipboard. Registry secrets are placed in `<option value>`. |
| F12 | LOW | No pre-scan of account flags, regular key, signer list, or account existence. A failed `account_info` only logs a line. |
| F13 | LOW | **Corrupted template literals in shipped code.** Line 331 and the SN grid at ~437 contain `` `\( {item.address ...} ( \){sec...})` `` — the `${` interpolations were mangled to `\(` `{`, so the labels render as literal text. |
| F14 | MEDIUM | **Version-dependent derivation.** `Wallet.fromEntropy(entropy)` is called with no `algorithm`. On xrpl 2.x the default was secp256k1; on 5.2.0 it is **ed25519**. Identical input, different address, depending on which CDN build loads. |

Clean results worth recording: **no `localStorage`, no `sessionStorage`, no `indexedDB`, no cookies, no
`fetch`/XHR exfiltration, no analytics, no secrets in URLs.** V7 does not leak secrets off-device. Its
failures are cryptographic and procedural, not exfiltration.

---

## 5. PRESERVE vs RETIRE

**Preserve into V8**
- The two transaction bodies (`SetRegularKey`, `AccountSet`/`SetFlag: 4`) — they are correct.
- Signing `asfDisableMaster` with the master key — protocol-required.
- Endpoint failover across multiple servers.
- Terminal-style operator log.
- Explicit network selection.
- XRPMAN identity: black + `#00FF00`.

**Retire**
- The "Universal Safe Key" package in full — secret numbers (F1, F2), mnemonics (F3), 24-byte entropy path.
- The bundled 1902-word list and `simpleChecksum`.
- `buffer` and `bip39` CDN scripts (F9) — unnecessary on xrpl 5.x.
- Checkbox-only attestation as a gate for irreversible operations (F4).
- Mainnet as the default network (F10).
- JSON registry file import of plaintext secrets (F11) in its current unvalidated form.

**Replace**
- Secret Numbers: use the **actual XRPL standard** — 8 groups of 6 digits, 5 data digits plus a
  `value * (position * 2 + 1) % 9` checksum digit, 8×uint16 big-endian → 16-byte entropy. Verified
  against `xrpl-secret-numbers@0.3.5` and confirmed to produce the same family seed as
  `Wallet.fromEntropy`. Reversible, checksummed, interoperable with Xaman.
- Algorithm ambiguity (F14): derive **both** secp256k1 and ed25519 candidates from entropy input and let
  the ledger scan decide which account actually exists.

---

## 6. GATE

We can state exactly what V7 does, exactly where it is unsound, and exactly which behaviour V8 must keep.
Phase 1 is closed.
