/**
 * XRPMAN REKEY V8 — failure-path test suite (Phase 11).
 *
 * Runs the shipped browser modules against the vendored xrpl bundle under Node.
 * Covers the reversibility guarantees, the input classifier, and — most importantly —
 * the gate that stands in front of asfDisableMaster.
 *
 *   node tests/run.js
 */

import './load-xrpl.mjs';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';

const appSource = readFileSync(new URL('../src/app.js', import.meta.url), 'utf8');

const wallet = await import('../src/wallet.js');
const security = await import('../src/security.js');
const ledger = await import('../src/xrpl.js');

let passed = 0;
const failures = [];

function test(name, fn) {
  try {
    fn();
    passed += 1;
    console.log(`  \x1b[32mPASS\x1b[0m  ${name}`);
  } catch (error) {
    failures.push({ name, error });
    console.log(`  \x1b[31mFAIL\x1b[0m  ${name}\n        ${error.message}`);
  }
}

function section(title) {
  console.log(`\n\x1b[1m${title}\x1b[0m`);
}

/* ================================================================== *
 * Secret Numbers — reversibility
 * ================================================================== */

section('SECRET NUMBERS — REVERSIBILITY');

test('round-trips 10,000 random entropies without loss', () => {
  for (let i = 0; i < 10_000; i += 1) {
    const entropy = new Uint8Array(randomBytes(16));
    const groups = wallet.entropyToSecretNumbers(entropy);
    const restored = wallet.secretNumbersToEntropy(groups);
    assert.deepEqual(Array.from(restored), Array.from(entropy), `mismatch at iteration ${i}`);
  }
});

test('matches the xrpl-secret-numbers reference checksum formula', () => {
  // checksum = value * (position * 2 + 1) % 9
  assert.equal(wallet.calculateChecksum(0, 57164), (57164 * 1) % 9);
  assert.equal(wallet.calculateChecksum(7, 65535), (65535 * 15) % 9);
});

test('accepts a whitespace-separated secret number string', () => {
  const entropy = new Uint8Array(randomBytes(16));
  const groups = wallet.entropyToSecretNumbers(entropy);
  const restored = wallet.secretNumbersToEntropy(groups.join(' '));
  assert.deepEqual(Array.from(restored), Array.from(entropy));
});

test('rejects a corrupted checksum digit', () => {
  const groups = wallet.entropyToSecretNumbers(new Uint8Array(randomBytes(16)));
  const broken = [...groups];
  const digit = Number(broken[3][5]);
  broken[3] = broken[3].slice(0, 5) + String((digit + 1) % 10);
  assert.throws(() => wallet.secretNumbersToEntropy(broken), /checksum/i);
});

test('rejects the wrong number of digits', () => {
  assert.throws(() => wallet.secretNumbersToEntropy('123456 123456'), /8 blocks/i);
});

test('rejects a block above the 65535 ceiling', () => {
  assert.throws(
    () => wallet.secretNumbersToEntropy(['999990', '000000', '000000', '000000', '000000', '000000', '000000', '000000']),
    /65535|checksum/i,
  );
});

test('V7 REGRESSION: the retired encoding loses data (audit F1)', () => {
  // The exact V7 encoder/decoder pair, reproduced so the reason it was retired
  // stays provable rather than anecdotal.
  const v7encode = (bytes) =>
    Array.from({ length: 8 }, (_, i) => {
      const c = bytes.slice(i * 3, i * 3 + 3);
      const v = ((c[0] || 0) << 16) | ((c[1] || 0) << 8) | (c[2] || 0);
      return String(v % 1000000).padStart(6, '0');
    });
  const v7decode = (rows) => {
    const e = new Uint8Array(24);
    rows.forEach((v, i) => {
      e[i * 3] = (v >> 16) & 0xff;
      e[i * 3 + 1] = (v >> 8) & 0xff;
      e[i * 3 + 2] = v & 0xff;
    });
    return e;
  };

  let survived = 0;
  for (let i = 0; i < 2000; i += 1) {
    const bytes = Array.from(randomBytes(24));
    const restored = v7decode(v7encode(bytes).map(Number));
    if (bytes.every((b, j) => b === restored[j])) survived += 1;
  }
  assert.equal(survived, 0, `V7 encoding unexpectedly survived ${survived} round trips`);
});

/* ================================================================== *
 * Derivation
 * ================================================================== */

section('DERIVATION');

test('family seed yields exactly one candidate with the seed-encoded algorithm', () => {
  const generated = wallet.generateAuthority(wallet.ALGORITHMS.ED25519);
  const { kind, candidates } = wallet.deriveCandidates(generated.seed);
  assert.equal(kind, wallet.INPUT_KIND.FAMILY_SEED);
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].address, generated.address);
  assert.equal(candidates[0].algorithm, wallet.ALGORITHMS.ED25519);
});

test('secret numbers yield both algorithm candidates, one of which is the source', () => {
  const generated = wallet.generateAuthority(wallet.ALGORITHMS.SECP256K1);
  assert.ok(generated.secretNumbers, 'secp256k1 generation must emit secret numbers');
  const { kind, candidates } = wallet.deriveCandidates(generated.secretNumbers.join(' '));
  assert.equal(kind, wallet.INPUT_KIND.SECRET_NUMBERS);
  assert.equal(candidates.length, 2);
  assert.ok(candidates.some((c) => c.address === generated.address));
});

test('ed25519 generation withholds secret numbers (they would restore a different account)', () => {
  const generated = wallet.generateAuthority(wallet.ALGORITHMS.ED25519);
  assert.equal(generated.secretNumbers, null);
});

test('hex entropy yields both algorithm candidates', () => {
  const { kind, candidates } = wallet.deriveCandidates('00112233445566778899aabbccddeeff');
  assert.equal(kind, wallet.INPUT_KIND.HEX_ENTROPY);
  assert.equal(candidates.length, 2);
  assert.notEqual(candidates[0].address, candidates[1].address);
});

test('the two algorithms genuinely disagree on address (audit F14)', () => {
  const entropy = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
  const a = globalThis.xrpl.Wallet.fromEntropy(entropy, { algorithm: wallet.ALGORITHMS.SECP256K1 });
  const b = globalThis.xrpl.Wallet.fromEntropy(entropy, { algorithm: wallet.ALGORITHMS.ED25519 });
  assert.notEqual(a.address, b.address);
});

test('classifier recognises each supported format', () => {
  const generated = wallet.generateAuthority(wallet.ALGORITHMS.SECP256K1);
  assert.equal(wallet.classifySecret(generated.seed), wallet.INPUT_KIND.FAMILY_SEED);
  assert.equal(wallet.classifySecret(generated.secretNumbers.join(' ')), wallet.INPUT_KIND.SECRET_NUMBERS);
  assert.equal(wallet.classifySecret('00112233445566778899aabbccddeeff'), wallet.INPUT_KIND.HEX_ENTROPY);
  assert.equal(wallet.classifySecret(''), wallet.INPUT_KIND.UNKNOWN);
  assert.equal(wallet.classifySecret('not a secret'), wallet.INPUT_KIND.UNKNOWN);
});

test('unrecognised input is refused rather than guessed at', () => {
  assert.throws(() => wallet.deriveCandidates('rrrrrrrrrrrrrrrrr'), /Unrecognised secret format/);
});

test('malformed secret numbers are refused', () => {
  assert.throws(() => wallet.deriveCandidates('11111 22222 33333'), /Unrecognised secret format/);
});

/* ================================================================== *
 * Regular key validation
 * ================================================================== */

section('REGULAR KEY VALIDATION');

test('rejects a regular key equal to the account (temBAD_REGKEY)', () => {
  const account = wallet.generateAuthority().address;
  assert.throws(() => wallet.assertUsableRegularKey(account, account), /cannot equal the account/);
});

test('rejects a malformed address', () => {
  assert.throws(() => wallet.assertUsableRegularKey('rNOTVALID', 'rXXX'), /not a valid XRPL/);
  assert.throws(() => wallet.assertUsableRegularKey('', 'rXXX'), /not a valid XRPL/);
});

test('accepts a distinct valid address', () => {
  const a = wallet.generateAuthority().address;
  const b = wallet.generateAuthority().address;
  assert.doesNotThrow(() => wallet.assertUsableRegularKey(b, a));
});

/* ================================================================== *
 * Flag decoding
 * ================================================================== */

section('ACCOUNT FLAGS');

test('detects lsfDisableMaster', () => {
  assert.equal(security.decodeAccountFlags(0x00100000).disableMaster, true);
  assert.equal(security.decodeAccountFlags(0x00800000).disableMaster, false);
});

test('decodes a composite flag word', () => {
  const flags = security.decodeAccountFlags(0x00100000 | 0x00800000 | 0x01000000);
  assert.equal(flags.disableMaster, true);
  assert.equal(flags.defaultRipple, true);
  assert.equal(flags.depositAuth, true);
  assert.equal(flags.globalFreeze, false);
});

test('asfDisableMaster is SetFlag 4', () => {
  assert.equal(security.ASF_DISABLE_MASTER, 4);
});

/* ================================================================== *
 * Gates — the core invariant
 * ================================================================== */

section('GATES');

const ACCOUNT = 'rBmAviBpiFpLMSLJ3vBs1o3ZKEGCvzVqfY';
const AUTHORITY = 'rQhWct2fv4Vc4KRjRgMrxa8xPN9Zx9iLKV';

function completeContext(overrides = {}) {
  const scan = {
    address: ACCOUNT,
    exists: true,
    validated: true,
    masterKeyActive: true,
    regularKey: AUTHORITY,
  };
  return {
    scan: { ...scan },
    verifyScan: { ...scan },
    proofScan: { ...scan },
    masterWallet: { address: ACCOUNT },
    authorityWallet: { address: AUTHORITY },
    newAuthority: { address: AUTHORITY },
    backupConfirmed: true,
    disableAcknowledged: true,
    controlProof: { proven: true },
    networkStatus: { mismatch: false, stale: false },
    ...overrides,
  };
}

test('DISABLE_MASTER opens only when every requirement holds', () => {
  assert.equal(security.evaluateGate(security.GATE.DISABLE_MASTER, completeContext()).open, true);
});

test('DISABLE_MASTER stays shut when control is unproven — THE CORE V8 INVARIANT', () => {
  const result = security.evaluateGate(
    security.GATE.DISABLE_MASTER,
    completeContext({ controlProof: { proven: false } }),
  );
  assert.equal(result.open, false);
  assert.equal(result.checks.find((c) => c.id === 'control-proven').ok, false);
});

test('DISABLE_MASTER stays shut when a tesSUCCESS is the only evidence', () => {
  // The exact V7 failure: a submit result, no proof, no verified ledger read.
  const result = security.evaluateGate(
    security.GATE.DISABLE_MASTER,
    completeContext({ controlProof: null, proofScan: null }),
  );
  assert.equal(result.open, false);
});

test('DISABLE_MASTER stays shut when the ledger regular key differs', () => {
  const context = completeContext();
  context.proofScan.regularKey = 'rSOMEONEELSE1111111111111111111111';
  assert.equal(security.evaluateGate(security.GATE.DISABLE_MASTER, context).open, false);
});

test('DISABLE_MASTER stays shut without the master secret (tecNEED_MASTER_KEY)', () => {
  assert.equal(
    security.evaluateGate(security.GATE.DISABLE_MASTER, completeContext({ masterWallet: null })).open,
    false,
  );
});

test('DISABLE_MASTER stays shut without the typed acknowledgement', () => {
  assert.equal(
    security.evaluateGate(security.GATE.DISABLE_MASTER, completeContext({ disableAcknowledged: false })).open,
    false,
  );
});

test('DISABLE_MASTER stays shut when the master key is already disabled', () => {
  const context = completeContext();
  context.proofScan.masterKeyActive = false;
  assert.equal(security.evaluateGate(security.GATE.DISABLE_MASTER, context).open, false);
});

test('REKEY stays shut when the master key is already disabled', () => {
  const context = completeContext();
  context.scan.masterKeyActive = false;
  assert.equal(security.evaluateGate(security.GATE.REKEY, context).open, false);
});

test('REKEY stays shut on a network mismatch', () => {
  assert.equal(
    security.evaluateGate(security.GATE.REKEY, completeContext({ networkStatus: { mismatch: true } })).open,
    false,
  );
});

test('REKEY stays shut in watch-only mode (no master secret)', () => {
  assert.equal(
    security.evaluateGate(security.GATE.REKEY, completeContext({ masterWallet: null })).open,
    false,
  );
});

test('REKEY stays shut when backup is unconfirmed', () => {
  assert.equal(
    security.evaluateGate(security.GATE.REKEY, completeContext({ backupConfirmed: false })).open,
    false,
  );
});

test('REKEY stays shut when the authority equals the account', () => {
  assert.equal(
    security.evaluateGate(security.GATE.REKEY, completeContext({ newAuthority: { address: ACCOUNT } })).open,
    false,
  );
});

test('PROVE stays shut when the loaded secret derives a different address', () => {
  assert.equal(
    security.evaluateGate(
      security.GATE.PROVE,
      completeContext({ authorityWallet: { address: 'rDIFFERENT11111111111111111111111' } }),
    ).open,
    false,
  );
});

test('PROVE stays shut when the authority secret was never supplied', () => {
  assert.equal(
    security.evaluateGate(security.GATE.PROVE, completeContext({ authorityWallet: null })).open,
    false,
  );
});

test('gate evaluation survives a malformed context instead of throwing', () => {
  const result = security.evaluateGate(security.GATE.DISABLE_MASTER, {});
  assert.equal(result.open, false);
  assert.ok(result.checks.every((c) => c.ok === false));
});

/* ================================================================== *
 * Control proof
 * ================================================================== */

section('CONTROL PROOF');

const proofBase = {
  scan: { regularKey: AUTHORITY },
  expectedAddress: AUTHORITY,
  proofTx: { engineResult: 'tesSUCCESS', validated: true, hash: 'ABC' },
  authorityWallet: { address: AUTHORITY },
};

test('proven when all four conditions hold', () => {
  assert.equal(security.assessControlProof(proofBase).proven, true);
});

test('unproven when the transaction is not yet validated', () => {
  assert.equal(
    security.assessControlProof({ ...proofBase, proofTx: { ...proofBase.proofTx, validated: false } }).proven,
    false,
  );
});

test('unproven when the engine result is not tesSUCCESS', () => {
  assert.equal(
    security.assessControlProof({ ...proofBase, proofTx: { ...proofBase.proofTx, engineResult: 'tefMASTER_DISABLED' } })
      .proven,
    false,
  );
});

test('unproven when the ledger regular key does not match', () => {
  assert.equal(
    security.assessControlProof({ ...proofBase, scan: { regularKey: 'rOTHER111111111111111111111111111' } }).proven,
    false,
  );
});

test('unproven when no authority wallet is held', () => {
  assert.equal(security.assessControlProof({ ...proofBase, authorityWallet: null }).proven, false);
});

/* ================================================================== *
 * Preflight
 * ================================================================== */

section('PREFLIGHT WARNINGS');

function scanFixture(overrides = {}) {
  return {
    address: ACCOUNT,
    exists: true,
    masterKeyActive: true,
    regularKey: null,
    signerList: null,
    balanceXrp: '100.000000',
    spendableXrp: '99.000000',
    reserveXrp: 1,
    flags: security.decodeAccountFlags(0),
    ...overrides,
  };
}

test('a nonexistent account is an error', () => {
  const warnings = security.preflightWarnings(scanFixture({ exists: false }), { mismatch: false });
  assert.equal(warnings[0].level, 'error');
  assert.match(warnings[0].text, /does not exist/);
});

test('an already-disabled master key is an error', () => {
  const warnings = security.preflightWarnings(scanFixture({ masterKeyActive: false }), { mismatch: false });
  assert.ok(warnings.some((w) => w.level === 'error' && /already disabled/.test(w.text)));
});

test('an existing regular key is surfaced as a replacement warning', () => {
  const warnings = security.preflightWarnings(scanFixture({ regularKey: AUTHORITY }), { mismatch: false });
  assert.ok(warnings.some((w) => w.level === 'warn' && /REPLACES/.test(w.text)));
});

test('a signer list is surfaced', () => {
  const warnings = security.preflightWarnings(
    scanFixture({ signerList: { quorum: 2, entries: [{}, {}, {}] } }),
    { mismatch: false },
  );
  assert.ok(warnings.some((w) => /Signer list present/.test(w.text)));
});

test('a balance at the reserve floor is an error', () => {
  const warnings = security.preflightWarnings(scanFixture({ spendableXrp: '0.000000' }), { mismatch: false });
  assert.ok(warnings.some((w) => w.level === 'error' && /reserve/.test(w.text)));
});

test('a network mismatch is an error', () => {
  const warnings = security.preflightWarnings(scanFixture(), {
    mismatch: true,
    reportedNetworkId: 0,
    expectedNetworkId: 1,
  });
  assert.ok(warnings.some((w) => w.level === 'error' && /Network mismatch/.test(w.text)));
});

test('a stale validated ledger is a warning', () => {
  const warnings = security.preflightWarnings(scanFixture(), { mismatch: false, stale: true, ledgerAge: 300 });
  assert.ok(warnings.some((w) => w.level === 'warn' && /300s old/.test(w.text)));
});

/* ================================================================== *
 * Mainnet gate
 * ================================================================== */

section('MAINNET GATE');

test('mainnet is gated in this build', () => {
  assert.equal(ledger.MAINNET_ENABLED, false);
  assert.equal(ledger.NETWORKS.mainnet.gated, true);
});

test('constructing a mainnet link throws NETWORK_GATED', () => {
  assert.throws(() => new ledger.LedgerLink('mainnet'), (error) => error.code === 'NETWORK_GATED');
});

test('testnet is the default and is not gated', () => {
  assert.equal(ledger.DEFAULT_NETWORK, 'testnet');
  assert.equal(ledger.NETWORKS.testnet.gated, false);
});

test('an unknown network is refused', () => {
  assert.throws(() => new ledger.LedgerLink('nope'), (error) => error.code === 'UNKNOWN_NETWORK');
});

test('every declared endpoint is wss and appears in the page CSP', () => {
  const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
  const csp = html.match(/connect-src([^;]+);/)[1];
  for (const network of Object.values(ledger.NETWORKS)) {
    for (const endpoint of network.endpoints) {
      assert.ok(endpoint.startsWith('wss://'), `${endpoint} is not wss`);
      assert.ok(csp.includes(endpoint), `${endpoint} missing from CSP connect-src (audit F6)`);
    }
  }
});

/* ================================================================== *
 * Secret hygiene
 * ================================================================== */

section('SECRET HYGIENE');

test('no source file touches persistent storage or a URL parameter', () => {
  const dir = new URL('../src/', import.meta.url);
  const banned = /localStorage|sessionStorage|indexedDB|document\.cookie|location\.hash|location\.search|new XMLHttpRequest|fetch\(/;
  for (const file of readdirSync(dir)) {
    const source = readFileSync(new URL(file, dir), 'utf8');
    assert.ok(!banned.test(source), `${file} references a persistence or exfiltration API`);
  }
});

test('the audit report format carries no secret field', () => {
  const source = appSource;
  const report = source.slice(source.indexOf("'XRPMAN SECURITY AUDIT'"), source.indexOf("].join('\\n')"));
  assert.ok(!/seed|privateKey|secretNumbers|authorityWallet\.seed/i.test(report), 'report references key material');
});

test('wipeInput clears a value', () => {
  const fake = { value: 'sEdSECRETVALUE' };
  wallet.wipeInput(fake);
  assert.equal(fake.value, '');
});

/* ================================================================== *
 * Result
 * ================================================================== */

console.log(`\n${'─'.repeat(64)}`);
if (failures.length === 0) {
  console.log(`\x1b[32mALL ${passed} TESTS PASSED\x1b[0m`);
  process.exit(0);
} else {
  console.log(`\x1b[31m${failures.length} FAILED\x1b[0m, ${passed} passed`);
  for (const failure of failures) console.log(`  ${failure.name}: ${failure.error.message}`);
  process.exit(1);
}
