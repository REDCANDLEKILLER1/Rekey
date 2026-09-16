/**
 * XRPMAN REKEY V8 — offline integration drill.
 *
 * Drives the real LedgerLink, scanner and gates through the full eight-phase
 * sequence against a mock rippled that speaks the genuine request/response shapes.
 * Transactions are signed with real keys and the blobs are decoded and verified,
 * so the regular-key authorisation in phase 06 is checked cryptographically rather
 * than asserted.
 *
 *   node tests/integration.js
 */

import './load-xrpl.mjs';
import assert from 'node:assert/strict';

const wallet = await import('../src/wallet.js');
const security = await import('../src/security.js');
const { LedgerLink } = await import('../src/xrpl.js');

const xrpl = globalThis.xrpl;

let passed = 0;
const failures = [];

function step(name, fn) {
  return (async () => {
    try {
      await fn();
      passed += 1;
      console.log(`  \x1b[32mPASS\x1b[0m  ${name}`);
    } catch (error) {
      failures.push({ name, error });
      console.log(`  \x1b[31mFAIL\x1b[0m  ${name}\n        ${error.message}`);
    }
  })();
}

/* ------------------------------------------------------------------ *
 * Mock rippled
 * ------------------------------------------------------------------ */

class MockLedger {
  constructor(account) {
    this.accounts = new Map();
    this.transactions = new Map();
    this.ledgerIndex = 9_000_000;
    this.account = account;
    this.rejectNext = null;
    this.submitted = [];

    this.accounts.set(account, {
      Account: account,
      Balance: '100000000',
      Flags: 0,
      OwnerCount: 0,
      Sequence: 100,
    });
  }

  isConnected() {
    return true;
  }

  async connect() {}
  async disconnect() {}

  async request(payload) {
    this.ledgerIndex += 1;
    switch (payload.command) {
      case 'server_info':
        return {
          result: {
            info: {
              network_id: 1,
              build_version: 'mock',
              server_state: 'full',
              validated_ledger: {
                seq: this.ledgerIndex,
                age: 2,
                reserve_base_xrp: 1,
                reserve_inc_xrp: 0.2,
              },
            },
          },
        };

      case 'account_info': {
        const data = this.accounts.get(payload.account);
        if (!data) {
          const error = new Error('Account not found.');
          error.data = { error: 'actNotFound' };
          throw error;
        }
        return {
          result: {
            account_data: { ...data },
            ...(this.signerListsAtRoot ? { signer_lists: this.signerListsAtRoot } : {}),
            ledger_index: this.ledgerIndex,
            validated: true,
          },
        };
      }

      case 'ledger':
        return { result: { ledger_index: this.ledgerIndex } };

      case 'tx': {
        const record = this.transactions.get(payload.transaction);
        if (!record) throw new Error('txnNotFound');
        return {
          result: { validated: true, meta: { TransactionResult: record.result }, ledger_index: record.ledgerIndex },
        };
      }

      default:
        throw new Error(`mock: unhandled command ${payload.command}`);
    }
  }

  async autofill(tx) {
    const data = this.accounts.get(tx.Account);
    if (!data) throw new Error('autofill: unknown account');
    return { ...tx, Fee: '12', Sequence: data.Sequence, LastLedgerSequence: this.ledgerIndex + 20 };
  }

  async submitAndWait(blob) {
    const decoded = xrpl.decode(blob);
    this.submitted.push(decoded);
    this.ledgerIndex += 1;

    const account = this.accounts.get(decoded.Account);
    const signer = xrpl.deriveAddress(decoded.SigningPubKey);
    const hash = `HASH${String(this.submitted.length).padStart(60, '0')}`;

    let result = this.rejectNext;
    this.rejectNext = null;

    if (!result) {
      const masterAllowed = signer === decoded.Account && !(account.Flags & security.LSF.DISABLE_MASTER);
      const regularAllowed = account.RegularKey && signer === account.RegularKey;

      if (!masterAllowed && !regularAllowed) {
        result = 'tefBAD_AUTH';
      } else if (decoded.TransactionType === 'SetRegularKey') {
        account.RegularKey = decoded.RegularKey;
        result = 'tesSUCCESS';
      } else if (decoded.TransactionType === 'AccountSet' && decoded.SetFlag === security.ASF_DISABLE_MASTER) {
        // rippled requires the master key pair for asfDisableMaster, and an
        // alternative signing method to already exist.
        if (signer !== decoded.Account) result = 'tecNEED_MASTER_KEY';
        else if (!account.RegularKey) result = 'tecNO_ALTERNATIVE_KEY';
        else {
          account.Flags |= security.LSF.DISABLE_MASTER;
          result = 'tesSUCCESS';
        }
      } else {
        result = 'tesSUCCESS';
      }
    }

    if (result === 'tesSUCCESS') account.Sequence += 1;
    this.transactions.set(hash, { result, ledgerIndex: this.ledgerIndex });

    return { result: { hash, validated: true, ledger_index: this.ledgerIndex, meta: { TransactionResult: result } } };
  }
}

function linkTo(mock) {
  const link = new LedgerLink('testnet');
  link.client = mock;
  link.endpoint = 'wss://mock';
  return link;
}

/* ------------------------------------------------------------------ *
 * Drill
 * ------------------------------------------------------------------ */

console.log('\n\x1b[1mOFFLINE INTEGRATION DRILL — FULL EIGHT-PHASE SEQUENCE\x1b[0m');

const master = xrpl.Wallet.generate();
const mock = new MockLedger(master.address);
const link = linkTo(mock);

const context = {
  masterWallet: master,
  backupConfirmed: true,
  disableAcknowledged: true,
};

await step('01 SCAN — reports an untouched account from a validated ledger', async () => {
  context.networkStatus = await link.verifyNetwork();
  assert.equal(context.networkStatus.mismatch, false);
  assert.equal(context.networkStatus.stale, false);

  context.scan = await security.scanAccount(link, master.address, context.networkStatus);
  assert.equal(context.scan.exists, true);
  assert.equal(context.scan.masterKeyActive, true);
  assert.equal(context.scan.regularKey, null);
  assert.equal(context.scan.signerList, null);
  assert.equal(context.scan.sequence, 100);
  assert.equal(security.describePosture(context.scan), 'MASTER ACTIVE // NO REGULAR KEY');
});

await step('02 AUTHORITY — generates a distinct local authority', async () => {
  const authority = wallet.generateAuthority(wallet.ALGORITHMS.SECP256K1);
  wallet.assertUsableRegularKey(authority.address, context.scan.address);
  context.newAuthority = { address: authority.address, algorithm: authority.algorithm };
  context.authorityWallet = authority.wallet;
  context.authoritySecretNumbers = authority.secretNumbers;
  assert.notEqual(authority.address, master.address);
});

await step('03 NEW KEY — the emitted secret numbers restore the same authority', async () => {
  const restored = wallet.deriveCandidates(context.authoritySecretNumbers.join(' '));
  assert.ok(restored.candidates.some((c) => c.address === context.newAuthority.address));
});

await step('04 REKEY GATE — opens only once every precondition is met', async () => {
  assert.equal(security.evaluateGate(security.GATE.REKEY, { ...context, backupConfirmed: false }).open, false);
  const gate = security.evaluateGate(security.GATE.REKEY, context);
  assert.equal(gate.open, true, gate.checks.filter((c) => !c.ok).map((c) => c.id).join(','));
});

await step('04 REKEY — submits SetRegularKey signed by the master key', async () => {
  const result = await link.signAndSubmit(
    { TransactionType: 'SetRegularKey', Account: context.scan.address, RegularKey: context.newAuthority.address },
    master,
  );
  context.rekeyTx = result;
  assert.equal(result.engineResult, 'tesSUCCESS');

  const submitted = mock.submitted.at(-1);
  assert.equal(submitted.TransactionType, 'SetRegularKey');
  assert.equal(submitted.Account, master.address);
  assert.equal(submitted.RegularKey, context.newAuthority.address);
  assert.equal(xrpl.deriveAddress(submitted.SigningPubKey), master.address, 'must be master-signed');
});

await step('05 VERIFY — the validated ledger carries the expected RegularKey', async () => {
  context.verifyScan = await security.scanAccount(link, context.scan.address, context.networkStatus);
  assert.equal(context.verifyScan.regularKey, context.newAuthority.address);
  assert.equal(context.verifyScan.validated, true);

  const lookup = await link.transaction(context.rekeyTx.hash);
  assert.equal(lookup.engineResult, 'tesSUCCESS');
  assert.equal(lookup.validated, true);
});

await step('DISABLE GATE — shut at this point, control is still unproven', async () => {
  context.proofScan = context.verifyScan;
  const gate = security.evaluateGate(security.GATE.DISABLE_MASTER, context);
  assert.equal(gate.open, false);
  assert.equal(gate.checks.find((c) => c.id === 'control-proven').ok, false);
});

await step('06 PROVE — a no-op AccountSet is signed by the regular key, not the master', async () => {
  const result = await link.signAndSubmit(
    { TransactionType: 'AccountSet', Account: context.scan.address },
    context.authorityWallet,
  );
  context.proofTx = result;
  assert.equal(result.engineResult, 'tesSUCCESS');

  const submitted = mock.submitted.at(-1);
  assert.equal(submitted.TransactionType, 'AccountSet');
  assert.equal(submitted.Account, master.address, 'Account stays the original account');
  assert.equal(submitted.SetFlag, undefined, 'the proof transaction must set no flag');
  assert.equal(submitted.ClearFlag, undefined, 'the proof transaction must clear no flag');
  assert.equal(
    xrpl.deriveAddress(submitted.SigningPubKey),
    context.newAuthority.address,
    'SigningPubKey must be the regular key',
  );
  assert.notEqual(xrpl.deriveAddress(submitted.SigningPubKey), master.address);
});

await step('06 PROVE — the proof signature verifies cryptographically', async () => {
  const submitted = mock.submitted.at(-1);
  assert.equal(xrpl.verifySignature(submitted), true);
});

await step('06 PROVE — all four control conditions register', async () => {
  const scan = await security.scanAccount(link, context.scan.address, context.networkStatus);
  context.proofScan = scan;
  const confirmed = { ...context.proofTx, ...(await link.transaction(context.proofTx.hash)) };
  context.controlProof = security.assessControlProof({
    scan,
    expectedAddress: context.newAuthority.address,
    proofTx: confirmed,
    authorityWallet: context.authorityWallet,
  });
  assert.deepEqual(
    {
      derivedMatch: context.controlProof.derivedMatch,
      ledgerMatch: context.controlProof.ledgerMatch,
      signatureValid: context.controlProof.signatureValid,
      txValidated: context.controlProof.txValidated,
      proven: context.controlProof.proven,
    },
    { derivedMatch: true, ledgerMatch: true, signatureValid: true, txValidated: true, proven: true },
  );
});

await step('07 DISABLE GATE — now open', async () => {
  const gate = security.evaluateGate(security.GATE.DISABLE_MASTER, context);
  assert.equal(gate.open, true, gate.checks.filter((c) => !c.ok).map((c) => c.id).join(','));
});

await step('07 DISABLE — AccountSet SetFlag 4 signed by the master key', async () => {
  const result = await link.signAndSubmit(
    { TransactionType: 'AccountSet', Account: context.scan.address, SetFlag: security.ASF_DISABLE_MASTER },
    master,
  );
  context.disableTx = result;
  assert.equal(result.engineResult, 'tesSUCCESS');

  const submitted = mock.submitted.at(-1);
  assert.equal(submitted.SetFlag, 4);
  assert.equal(xrpl.deriveAddress(submitted.SigningPubKey), master.address);
});

await step('08 AUDIT — final scan shows master disabled and the regular key in place', async () => {
  const scan = await security.scanAccount(link, context.scan.address, context.networkStatus);
  assert.equal(scan.masterKeyActive, false);
  assert.equal(scan.flags.disableMaster, true);
  assert.equal(scan.regularKey, context.newAuthority.address);
  assert.equal(security.describePosture(scan), 'MASTER DISABLED // REGULAR KEY SET');
});

/* ------------------------------------------------------------------ *
 * Failure paths
 * ------------------------------------------------------------------ */

console.log('\n\x1b[1mFAILURE PATHS\x1b[0m');

await step('a regular key cannot disable the master key (tecNEED_MASTER_KEY)', async () => {
  const owner = xrpl.Wallet.generate();
  const fixture = new MockLedger(owner.address);
  const fixtureLink = linkTo(fixture);
  const authority = wallet.generateAuthority();

  await fixtureLink.signAndSubmit(
    { TransactionType: 'SetRegularKey', Account: owner.address, RegularKey: authority.address },
    owner,
  );
  const result = await fixtureLink.signAndSubmit(
    { TransactionType: 'AccountSet', Account: owner.address, SetFlag: security.ASF_DISABLE_MASTER },
    authority.wallet,
  );
  assert.equal(result.engineResult, 'tecNEED_MASTER_KEY');
});

await step('the master key cannot be disabled with no alternative (tecNO_ALTERNATIVE_KEY)', async () => {
  const owner = xrpl.Wallet.generate();
  const fixtureLink = linkTo(new MockLedger(owner.address));
  const result = await fixtureLink.signAndSubmit(
    { TransactionType: 'AccountSet', Account: owner.address, SetFlag: security.ASF_DISABLE_MASTER },
    owner,
  );
  assert.equal(result.engineResult, 'tecNO_ALTERNATIVE_KEY');
});

await step('a rejected rekey leaves the ledger unchanged and the gate shut', async () => {
  const owner = xrpl.Wallet.generate();
  const fixture = new MockLedger(owner.address);
  const fixtureLink = linkTo(fixture);
  const authority = wallet.generateAuthority();

  fixture.rejectNext = 'tecINSUFFICIENT_RESERVE';
  const result = await fixtureLink.signAndSubmit(
    { TransactionType: 'SetRegularKey', Account: owner.address, RegularKey: authority.address },
    owner,
  );
  assert.equal(result.engineResult, 'tecINSUFFICIENT_RESERVE');

  const status = await fixtureLink.verifyNetwork();
  const scan = await security.scanAccount(fixtureLink, owner.address, status);
  assert.equal(scan.regularKey, null);
  assert.equal(
    security.evaluateGate(security.GATE.DISABLE_MASTER, {
      scan,
      proofScan: scan,
      newAuthority: { address: authority.address },
      masterWallet: owner,
      backupConfirmed: true,
      disableAcknowledged: true,
      networkStatus: status,
      controlProof: null,
    }).open,
    false,
  );
});

await step('a nonexistent account is reported rather than thrown', async () => {
  const fixtureLink = linkTo(new MockLedger(xrpl.Wallet.generate().address));
  const status = await fixtureLink.verifyNetwork();
  const scan = await security.scanAccount(fixtureLink, 'rNoAccount111111111111111111111111', status);
  assert.equal(scan.exists, false);
  assert.equal(scan.masterKeyActive, null);
  const warnings = security.preflightWarnings(scan, status);
  assert.equal(warnings[0].level, 'error');
});

await step('a network mismatch is detected from server_info', async () => {
  const fixture = new MockLedger(xrpl.Wallet.generate().address);
  const originalRequest = fixture.request.bind(fixture);
  fixture.request = async (payload) => {
    const response = await originalRequest(payload);
    if (payload.command === 'server_info') response.result.info.network_id = 0;
    return response;
  };
  const status = await linkTo(fixture).verifyNetwork();
  assert.equal(status.mismatch, true);
  assert.equal(status.reportedNetworkId, 0);
  assert.equal(status.expectedNetworkId, 1);
});

await step('a stale validated ledger is flagged', async () => {
  const fixture = new MockLedger(xrpl.Wallet.generate().address);
  const originalRequest = fixture.request.bind(fixture);
  fixture.request = async (payload) => {
    const response = await originalRequest(payload);
    if (payload.command === 'server_info') response.result.info.validated_ledger.age = 900;
    return response;
  };
  const status = await linkTo(fixture).verifyNetwork();
  assert.equal(status.stale, true);
  assert.equal(status.ledgerAge, 900);
});

await step('an existing regular key and signer list are both detected', async () => {
  const owner = xrpl.Wallet.generate();
  const other = xrpl.Wallet.generate();
  const fixture = new MockLedger(owner.address);
  const record = fixture.accounts.get(owner.address);
  record.RegularKey = other.address;
  const signerLists = [
    {
      SignerQuorum: 2,
      SignerEntries: [
        { SignerEntry: { Account: other.address, SignerWeight: 1 } },
        { SignerEntry: { Account: owner.address, SignerWeight: 1 } },
      ],
    },
  ];
  // Serve it the way rippled API v2 does: at the result root, not inside account_data.
  fixture.signerListsAtRoot = signerLists;

  const fixtureLink = linkTo(fixture);
  const status = await fixtureLink.verifyNetwork();
  const scan = await security.scanAccount(fixtureLink, owner.address, status);
  assert.equal(scan.regularKey, other.address);
  assert.equal(scan.signerList.quorum, 2);
  assert.equal(scan.signerList.entries.length, 2);

  const warnings = security.preflightWarnings(scan, status);
  assert.ok(warnings.some((w) => /REPLACES/.test(w.text)));
  assert.ok(warnings.some((w) => /Signer list present/.test(w.text)));
});

await step('an already-disabled master key blocks the rekey gate', async () => {
  const owner = xrpl.Wallet.generate();
  const fixture = new MockLedger(owner.address);
  fixture.accounts.get(owner.address).Flags = security.LSF.DISABLE_MASTER;
  const fixtureLink = linkTo(fixture);
  const status = await fixtureLink.verifyNetwork();
  const scan = await security.scanAccount(fixtureLink, owner.address, status);

  assert.equal(scan.masterKeyActive, false);
  assert.equal(
    security.evaluateGate(security.GATE.REKEY, {
      scan,
      masterWallet: owner,
      newAuthority: { address: wallet.generateAuthority().address },
      backupConfirmed: true,
      networkStatus: status,
    }).open,
    false,
  );
});

await step('a wrong authority secret cannot satisfy the proof gate', async () => {
  const intended = wallet.generateAuthority();
  const wrong = wallet.generateAuthority();
  const scan = { regularKey: intended.address, address: 'rX', masterKeyActive: true, exists: true, validated: true };
  assert.equal(
    security.evaluateGate(security.GATE.PROVE, {
      verifyScan: scan,
      newAuthority: { address: intended.address },
      authorityWallet: wrong.wallet,
    }).open,
    false,
  );
});

console.log(`\n${'─'.repeat(64)}`);
if (failures.length === 0) {
  console.log(`\x1b[32mALL ${passed} INTEGRATION STEPS PASSED\x1b[0m`);
  process.exit(0);
} else {
  console.log(`\x1b[31m${failures.length} FAILED\x1b[0m, ${passed} passed`);
  process.exit(1);
}
