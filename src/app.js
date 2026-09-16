/**
 * XRPMAN REKEY V8 — app.js
 * Wizard orchestration.
 *
 * SCAN → UNDERSTAND → REKEY → VERIFY → PROVE → LOCK → AUDIT
 *
 * The rule this application exists to enforce: the master key is never disabled
 * because a previous transaction returned tesSUCCESS. Every stage re-reads a
 * validated ledger, and step 07 additionally requires a transaction that the new
 * key itself signed and the ledger validated.
 */

import * as ui from './ui.js';
import {
  ALGORITHMS,
  ALGORITHM_LABEL,
  assertUsableRegularKey,
  classifySecret,
  deriveCandidates,
  generateAuthority,
  isValidAddress,
  wipeInput,
} from './wallet.js';
import { LedgerLink, MAINNET_ENABLED, NETWORKS, DEFAULT_NETWORK } from './xrpl.js';
import {
  ASF_DISABLE_MASTER,
  GATE,
  assessControlProof,
  describePosture,
  evaluateGate,
  preflightWarnings,
  scanAccount,
} from './security.js';

/* ------------------------------------------------------------------ *
 * State — memory only. Nothing below is ever persisted.
 * ------------------------------------------------------------------ */

const state = {
  networkId: DEFAULT_NETWORK,
  link: null,
  networkStatus: null,

  inputMode: 'secret',
  candidates: [],
  selectedCandidate: -1,
  masterWallet: null,
  scan: null,

  authorityMode: 'generate',
  newAuthority: null,
  authorityWallet: null,
  backupConfirmed: false,

  rekeyTx: null,
  verifyScan: null,
  proofTx: null,
  proofScan: null,
  controlProof: null,

  disableAcknowledged: false,
  disableTx: null,
  finalScan: null,

  stage: 0,
  completed: new Set(),
  busy: false,
};

const receipts = [];

/* ------------------------------------------------------------------ *
 * Busy guard — the single defence against double-click and double-submit.
 * ------------------------------------------------------------------ */

function guard(buttonId, task) {
  return async (...args) => {
    if (state.busy) {
      ui.log('Operation already in progress — ignoring duplicate request.', 'warn');
      return;
    }
    state.busy = true;
    ui.setBusy(true);
    if (buttonId) ui.setDisabled(buttonId, true);
    try {
      await task(...args);
    } catch (error) {
      ui.log(error?.message || String(error), 'error');
      console.error(error);
    } finally {
      state.busy = false;
      ui.setBusy(false);
      refreshGates();
    }
  };
}

/* ------------------------------------------------------------------ *
 * Stage control
 * ------------------------------------------------------------------ */

function setStage(index) {
  state.stage = index;
  ui.renderRail(index, state.completed);
  const step = ui.STEPS[index];
  ui.setChip('chip-stage', `${step.n} ${step.label.toUpperCase()}`, 'ok');
  ui.STEPS.forEach((s, i) => {
    if (state.completed.has(i)) ui.setPanelState(s.id, 'done');
    else if (i === index) ui.setPanelState(s.id, 'active');
    else if (i < index) ui.setPanelState(s.id, 'done');
  });
}

function completeStage(index, nextIndex) {
  state.completed.add(index);
  ui.setText(`${ui.STEPS[index].id}-status`, 'COMPLETE');
  if (nextIndex !== undefined && nextIndex !== null) {
    ui.setPanelState(ui.STEPS[nextIndex].id, 'active');
    ui.setText(`${ui.STEPS[nextIndex].id}-status`, 'READY');
    setStage(nextIndex);
    ui.focusPanel(ui.STEPS[nextIndex].id);
  } else {
    setStage(index);
  }
}

/* ------------------------------------------------------------------ *
 * Connection
 * ------------------------------------------------------------------ */

async function ensureLink() {
  if (state.link && state.link.network.id !== state.networkId) {
    await state.link.disconnect();
    state.link = null;
  }
  if (!state.link) state.link = new LedgerLink(state.networkId);
  if (!state.link.connected) {
    ui.log(`Connecting to ${state.link.network.label}...`, 'info');
    const endpoint = await state.link.connect((url) => ui.log(`Trying ${url}`, 'info'));
    ui.log(`Connected: ${endpoint}`, 'success');
  }

  state.networkStatus = await state.link.verifyNetwork();
  const status = state.networkStatus;

  ui.setChip(
    'chip-network',
    `${state.link.network.label}${status.mismatch ? ' MISMATCH' : ''}`,
    status.mismatch ? 'danger' : 'ok',
  );
  ui.setChip(
    'chip-ledger',
    status.ledgerIndex ? `${status.ledgerIndex}${status.stale ? ` +${status.ledgerAge}s` : ''}` : '—',
    status.stale ? 'warn' : 'ok',
  );

  if (status.mismatch) {
    throw new Error(
      `Network mismatch — endpoint reports network_id ${status.reportedNetworkId}, expected ${status.expectedNetworkId}. Refusing to continue.`,
    );
  }
  if (status.stale) {
    ui.log(`Validated ledger is ${status.ledgerAge}s old — node may be lagging.`, 'warn');
  }
  return state.link;
}

/* ------------------------------------------------------------------ *
 * 01 SCAN
 * ------------------------------------------------------------------ */

const doScan = guard('btn-scan', async () => {
  ui.logStep('01 SCAN');
  ui.renderNotices('p1-notices', []);
  state.masterWallet = null;
  state.candidates = [];
  state.selectedCandidate = -1;

  const link = await ensureLink();
  let addresses = [];

  if (state.inputMode === 'watch') {
    const address = ui.$('src-address').value.trim();
    if (!isValidAddress(address)) throw new Error('Not a valid XRPL classic address.');
    addresses = [{ address, algorithm: null, wallet: null, note: 'watch only' }];
    ui.log('Watch-only mode — no secret loaded.', 'warn');
  } else {
    const raw = ui.$('src-secret').value;
    if (!raw.trim()) throw new Error('Enter a secret, or switch to watch-only mode.');
    const kind = classifySecret(raw);
    ui.log(`Input classified as ${kind}.`, 'info');
    const derived = deriveCandidates(raw);
    addresses = derived.candidates;
    if (addresses.length > 1) {
      ui.log(
        `${addresses.length} candidate addresses — entropy input does not encode its algorithm. Resolving against the ledger.`,
        'warn',
      );
    }
  }

  // Probe every candidate before choosing. This is what resolves the secp256k1 /
  // ed25519 ambiguity that silently changed behaviour between xrpl 2.x and 5.x.
  const probed = [];
  for (const entry of addresses) {
    const info = await link.accountInfo(entry.address);
    probed.push({
      ...entry,
      exists: info.exists,
      balanceXrp: info.exists ? (Number(info.data.Balance) / 1e6).toFixed(6) : '0',
      algorithmLabel: entry.algorithm ? ALGORITHM_LABEL[entry.algorithm] : 'WATCH ONLY',
    });
    ui.log(
      `${entry.address} · ${entry.algorithm ? ALGORITHM_LABEL[entry.algorithm] : 'WATCH'} · ${
        info.exists ? 'FUNDED' : 'NOT FOUND'
      }`,
      info.exists ? 'success' : 'warn',
    );
  }

  state.candidates = probed;
  const funded = probed.filter((c) => c.exists);
  const chosen = funded.length === 1 ? probed.indexOf(funded[0]) : probed.length === 1 ? 0 : -1;

  if (probed.length > 1) {
    renderCandidatePicker(chosen);
  } else {
    ui.clear(ui.$('p1-candidates'));
  }

  if (chosen < 0) {
    ui.renderNotices('p1-notices', [
      {
        level: funded.length === 0 ? 'error' : 'warn',
        text:
          funded.length === 0
            ? 'No candidate address exists on this network. Wrong network, wrong secret, or the account is unfunded.'
            : 'Multiple candidates are funded. Select the account you intend to rekey.',
      },
    ]);
    return;
  }

  await selectCandidate(chosen);
});

function renderCandidatePicker(selectedIndex) {
  ui.renderCandidates(
    'p1-candidates',
    state.candidates.map((c, i) => ({ ...c, selected: i === selectedIndex })),
    'candidate',
    (index) => {
      guard(null, () => selectCandidate(index))();
    },
  );
}

async function selectCandidate(index) {
  const candidate = state.candidates[index];
  if (!candidate) return;
  state.selectedCandidate = index;
  state.masterWallet = candidate.wallet || null;

  const link = await ensureLink();
  const scan = await scanAccount(link, candidate.address, state.networkStatus);
  state.scan = scan;

  renderAccountHud(scan);
  const warnings = preflightWarnings(scan, state.networkStatus);
  ui.renderNotices('p1-notices', warnings);
  warnings.forEach((warning) => ui.log(warning.text, warning.level === 'error' ? 'error' : 'warn'));

  ui.setChip('chip-account', shortAddress(scan.address), scan.exists ? 'ok' : 'danger');
  ui.setText('p1-status', describePosture(scan));
  ui.log(`Scan complete: ${describePosture(scan)}`, 'success');

  const blocking = warnings.some((warning) => warning.level === 'error');
  if (!blocking && scan.exists) {
    completeStage(0, 1);
  } else {
    ui.setPanelState('p2', 'locked');
  }
}

function renderAccountHud(scan) {
  ui.renderReadout('p1-readout', [
    ['NETWORK', state.link.network.label, 'ok'],
    ['ENDPOINT', state.link.endpoint, 'none'],
    ['ACCOUNT', scan.address, 'ok'],
    ['EXISTS', scan.exists ? 'YES' : 'NO', scan.exists ? 'ok' : 'bad'],
    ['BALANCE', scan.exists ? `${scan.balanceXrp} XRP` : '—', 'ok'],
    ['RESERVE', scan.reserveXrp === null ? 'UNKNOWN' : `${scan.reserveXrp.toFixed(6)} XRP`, 'none'],
    ['SPENDABLE', scan.spendableXrp === null ? 'UNKNOWN' : `${scan.spendableXrp} XRP`, 'none'],
    [
      'MASTER KEY',
      scan.masterKeyActive === null ? '—' : scan.masterKeyActive ? 'ACTIVE' : 'DISABLED',
      scan.masterKeyActive ? 'ok' : 'bad',
    ],
    ['REGULAR KEY', scan.regularKey || 'NONE', scan.regularKey ? 'warn' : 'none'],
    [
      'SIGNER LIST',
      scan.signerList
        ? `${scan.signerList.entries.length} SIGNERS · QUORUM ${scan.signerList.quorum}`
        : 'NONE',
      scan.signerList ? 'warn' : 'none',
    ],
    ['ACCOUNT FLAGS', describeFlags(scan.flags), 'none'],
    ['SEQUENCE', scan.sequence === null ? '—' : String(scan.sequence).padStart(8, '0'), 'ok'],
    ['LEDGER', scan.ledgerIndex ? `${scan.ledgerIndex} VALIDATED` : 'VALIDATED', 'ok'],
  ]);
}

function describeFlags(flags) {
  const active = Object.entries(flags)
    .filter(([key, value]) => key !== 'raw' && value === true)
    .map(([key]) => key.replace(/([A-Z])/g, ' $1').toUpperCase().trim());
  return active.length ? active.join(', ') : 'NONE';
}

/* ------------------------------------------------------------------ *
 * 02 AUTHORITY
 * ------------------------------------------------------------------ */

const doGenerate = guard('btn-generate', async () => {
  ui.logStep('02 AUTHORITY — GENERATE');
  const algorithm = ui.$('auth-algorithm').value;
  const authority = generateAuthority(algorithm);

  assertUsableRegularKey(authority.address, state.scan.address);

  state.newAuthority = {
    address: authority.address,
    algorithm: authority.algorithm,
    generated: true,
  };
  state.authorityWallet = authority.wallet;

  const entries = [
    {
      label: 'FAMILY SEED — THIS IS THE PRIVATE KEY',
      value: authority.seed,
      hint: 'Anyone holding this controls the account after the rekey. Store it offline.',
    },
  ];
  if (authority.secretNumbers) {
    entries.push({
      label: 'XRPL SECRET NUMBERS — 8 BLOCKS, CHECKSUMMED',
      groups: authority.secretNumbers,
      hint: 'Standard XRPL secret numbers. Restores the same account in Xaman and any compliant tool.',
    });
  }
  ui.renderSecretBlock('p3-secrets', entries);

  ui.renderReadout('p3-readout', [
    ['NEW AUTHORITY', authority.address, 'ok'],
    ['ALGORITHM', ALGORITHM_LABEL[authority.algorithm], 'ok'],
    ['PUBLIC KEY', authority.publicKey, 'none'],
    ['SECRET HELD IN TAB', 'YES — CONTROL CAN BE PROVEN AT STEP 06', 'ok'],
  ]);

  ui.log(`Generated new authority ${authority.address} (${ALGORITHM_LABEL[authority.algorithm]}).`, 'success');
  ui.renderNotices('p2-notices', []);
  completeStage(1, 2);
});

const doUseExisting = guard('btn-use-existing', async () => {
  ui.logStep('02 AUTHORITY — EXISTING');
  const address = ui.$('auth-address').value.trim();
  assertUsableRegularKey(address, state.scan.address);

  state.newAuthority = { address, algorithm: null, generated: false };
  state.authorityWallet = null;

  ui.clear(ui.$('p3-secrets'));
  ui.renderReadout('p3-readout', [
    ['NEW AUTHORITY', address, 'ok'],
    ['ALGORITHM', 'UNKNOWN — SUPPLIED AS ADDRESS', 'none'],
    ['SECRET HELD IN TAB', 'NO — REQUIRED AT STEP 06', 'warn'],
  ]);
  ui.renderNotices('p2-notices', [
    {
      level: 'warn',
      text: 'Step 07 stays locked until this key signs a validated transaction at step 06. That needs its secret.',
    },
  ]);

  ui.log(`Authority set to existing address ${address}.`, 'success');
  completeStage(1, 2);
});

/* ------------------------------------------------------------------ *
 * 03 NEW KEY — backup attestation
 * ------------------------------------------------------------------ */

function evaluateBackup() {
  const typed = ui.$('backup-confirm').value.trim();
  const checked = ui.$('chk-backup').checked;
  const matches = Boolean(state.newAuthority) && typed === state.newAuthority.address;
  state.backupConfirmed = matches && checked;
  ui.setDisabled('btn-lock-authority', !state.backupConfirmed);

  if (typed && !matches) {
    ui.renderNotices('p3-notices', [
      { level: 'warn', text: 'Typed address does not match the new authority address.' },
    ]);
  } else {
    ui.renderNotices('p3-notices', []);
  }
}

const doLockAuthority = guard('btn-lock-authority', async () => {
  if (!state.backupConfirmed) throw new Error('Backup not confirmed.');
  ui.logStep('03 NEW KEY — LOCKED');
  ui.log('Recovery credentials attested by the operator.', 'success');
  renderRekeyConfirmation();
  completeStage(2, 3);
});

function renderRekeyConfirmation() {
  ui.renderConfirm('p4-confirm', [
    ['SOURCE', state.scan.address],
    ['NEW REGULAR KEY', state.newAuthority.address],
    ['NETWORK', state.link.network.label],
    ['TRANSACTION', 'SetRegularKey'],
    ['SIGNED BY', 'MASTER KEY'],
  ]);
}

/* ------------------------------------------------------------------ *
 * 04 REKEY
 * ------------------------------------------------------------------ */

const doRekey = guard('btn-rekey', async () => {
  ui.logStep('04 REKEY');
  const gate = evaluateGate(GATE.REKEY, state);
  if (!gate.open) throw new Error('Rekey gate is not satisfied.');

  const link = await ensureLink();

  // Re-scan immediately before signing. The account may have changed since step 01.
  const fresh = await scanAccount(link, state.scan.address, state.networkStatus);
  if (!fresh.masterKeyActive) throw new Error('Master key is no longer active. Aborting.');
  if (fresh.regularKey === state.newAuthority.address) {
    ui.log('RegularKey already matches the target — skipping redundant submission.', 'warn');
    state.scan = fresh;
    state.verifyScan = fresh;
    completeStage(3, 4);
    await doVerifyInner();
    return;
  }
  state.scan = fresh;

  const transaction = {
    TransactionType: 'SetRegularKey',
    Account: fresh.address,
    RegularKey: state.newAuthority.address,
  };

  ui.log(`Submitting SetRegularKey → ${state.newAuthority.address}`, 'info');
  const result = await link.signAndSubmit(transaction, state.masterWallet);
  state.rekeyTx = result;
  recordReceipt('SETREGULARKEY', result);

  ui.log(`SetRegularKey result: ${result.engineResult} (${result.hash})`, resultTone(result));
  if (result.engineResult !== 'tesSUCCESS') {
    ui.renderNotices('p4-notices', [
      { level: 'error', text: `Transaction rejected: ${result.engineResult}. Nothing changed on the ledger.` },
    ]);
    throw new Error(`SetRegularKey failed: ${result.engineResult}`);
  }

  ui.renderNotices('p4-notices', [
    { level: 'warn', text: 'Submission succeeded. That is not yet evidence — step 05 re-reads the ledger.' },
  ]);
  completeStage(3, 4);
  await doVerifyInner();
});

/* ------------------------------------------------------------------ *
 * 05 VERIFY LEDGER
 * ------------------------------------------------------------------ */

const doVerify = guard('btn-verify', () => doVerifyInner());

async function doVerifyInner() {
  ui.logStep('05 VERIFY LEDGER');
  const link = await ensureLink();

  const scan = await scanAccount(link, state.scan.address, state.networkStatus);
  state.verifyScan = scan;

  let txCheck = null;
  if (state.rekeyTx?.hash) {
    try {
      txCheck = await link.transaction(state.rekeyTx.hash);
    } catch (error) {
      ui.log(`Transaction lookup failed: ${error.message}`, 'warn');
    }
  }

  const expected = state.newAuthority.address;
  const match = scan.regularKey === expected;

  ui.renderReadout('p5-readout', [
    ['SETREGULARKEY', txCheck ? txCheck.engineResult : state.rekeyTx?.engineResult || 'PRE-EXISTING', match ? 'ok' : 'bad'],
    ['LEDGER VALIDATED', txCheck ? (txCheck.validated ? 'YES' : 'NO') : scan.validated ? 'YES' : 'NO', 'ok'],
    ['EXPECTED KEY', expected, 'none'],
    ['LEDGER KEY', scan.regularKey || 'NONE', match ? 'ok' : 'bad'],
    ['RESULT', match ? 'MATCH' : 'MISMATCH', match ? 'ok' : 'bad'],
    ['LEDGER INDEX', scan.ledgerIndex, 'none'],
  ]);

  if (!match) {
    ui.renderNotices('p5-notices', [
      {
        level: 'error',
        text: `HARD STOP. Validated ledger reports RegularKey "${scan.regularKey || 'NONE'}", expected "${expected}". Step 06 stays locked.`,
      },
    ]);
    ui.setPanelState('p6', 'locked');
    ui.log('Ledger verification FAILED — mismatch.', 'error');
    return;
  }

  ui.renderNotices('p5-notices', [
    { level: 'info', text: 'RegularKey confirmed on a validated ledger. Control is still unproven.' },
  ]);
  ui.log('RegularKey verified against validated ledger.', 'success');

  ui.setHidden('p6-secret-wrap', Boolean(state.authorityWallet));
  completeStage(4, 5);
  renderProofReadout();
}

/* ------------------------------------------------------------------ *
 * 06 PROVE CONTROL
 * ------------------------------------------------------------------ */

const doLoadAuthoritySecret = guard('btn-load-authority', async () => {
  const raw = ui.$('auth-secret').value;
  if (!raw.trim()) throw new Error('Enter the new authority secret.');

  const derived = deriveCandidates(raw);
  const match = derived.candidates.find((c) => c.address === state.newAuthority.address);
  if (!match) {
    throw new Error(
      `That secret derives ${derived.candidates.map((c) => c.address).join(' / ')}, not ${state.newAuthority.address}.`,
    );
  }

  state.authorityWallet = match.wallet;
  state.newAuthority.algorithm = match.algorithm;
  wipeInput(ui.$('auth-secret'));
  ui.setHidden('p6-secret-wrap', true);
  ui.log(`Authority secret loaded — derives ${match.address}.`, 'success');
  renderProofReadout();
});

function renderProofReadout() {
  const proof = state.controlProof;
  ui.renderReadout('p6-readout', [
    [
      'DERIVED ADDRESS',
      state.authorityWallet ? state.authorityWallet.address : 'SECRET NOT LOADED',
      state.authorityWallet?.address === state.newAuthority?.address ? 'ok' : 'warn',
    ],
    [
      'REGULARKEY LEDGER',
      state.verifyScan?.regularKey || 'NONE',
      state.verifyScan?.regularKey === state.newAuthority?.address ? 'ok' : 'bad',
    ],
    ['SIGNATURE', proof ? (proof.signatureValid ? 'VALID' : 'REJECTED') : 'NOT ATTEMPTED', proof?.signatureValid ? 'ok' : 'none'],
    ['TRANSACTION', proof ? (proof.txValidated ? 'VALIDATED' : 'UNVALIDATED') : '—', proof?.txValidated ? 'ok' : 'none'],
    ['CONTROL', proof?.proven ? 'PROVEN ✓' : 'UNPROVEN', proof?.proven ? 'ok' : 'warn'],
  ]);
  refreshGates();
}

const doProve = guard('btn-prove', async () => {
  ui.logStep('06 PROVE CONTROL');
  const gate = evaluateGate(GATE.PROVE, state);
  if (!gate.open) throw new Error('Proof gate is not satisfied.');

  const link = await ensureLink();

  // A bare AccountSet changes nothing: it sets no flag, moves no value, and touches
  // no object. It costs the transaction fee and one sequence number. Its only purpose
  // is to make the ledger say whether the new key can authorise this account.
  const transaction = { TransactionType: 'AccountSet', Account: state.scan.address };

  ui.log('Submitting no-op AccountSet signed by the new regular key...', 'info');
  const result = await link.signAndSubmit(transaction, state.authorityWallet);
  state.proofTx = result;
  recordReceipt('CONTROL PROOF', result);
  ui.log(`Proof transaction result: ${result.engineResult} (${result.hash})`, resultTone(result));

  let confirmed = result;
  try {
    confirmed = { ...result, ...(await link.transaction(result.hash)) };
  } catch (error) {
    ui.log(`Proof lookup failed: ${error.message}`, 'warn');
  }

  const scan = await scanAccount(link, state.scan.address, state.networkStatus);
  state.proofScan = scan;

  state.controlProof = assessControlProof({
    scan,
    expectedAddress: state.newAuthority.address,
    proofTx: confirmed,
    authorityWallet: state.authorityWallet,
  });

  renderProofReadout();

  if (!state.controlProof.proven) {
    ui.renderNotices('p6-notices', [
      {
        level: 'error',
        text: `Control NOT proven (${confirmed.engineResult}). The master key stays enabled and step 07 remains locked.`,
      },
    ]);
    ui.log('CONTROL PROOF FAILED — master key untouched.', 'error');
    return;
  }

  ui.renderNotices('p6-notices', [
    { level: 'info', text: 'CONTROL PROVEN — the new key authorised a transaction the ledger validated.' },
  ]);
  ui.log('CONTROL PROVEN ✓', 'success');

  ui.renderConfirm(
    'p7-confirm',
    [
      ['ACCOUNT', state.scan.address],
      ['AUTHORISED BY AFTER THIS', state.newAuthority.address],
      ['NETWORK', state.link.network.label],
      ['TRANSACTION', 'AccountSet · SetFlag 4 (asfDisableMaster)'],
      ['SIGNED BY', 'MASTER KEY — required by protocol'],
      ['CONTROL PROOF', state.controlProof.hash || '—'],
    ],
    true,
  );

  completeStage(5, 6);
});

/* ------------------------------------------------------------------ *
 * 07 DISABLE MASTER
 * ------------------------------------------------------------------ */

function evaluateDisableAck() {
  const phrase = ui.$('disable-phrase').value.trim().toUpperCase();
  state.disableAcknowledged = ui.$('chk-disable').checked && phrase === 'DISABLE MASTER';
  refreshGates();
}

const doDisable = guard('btn-disable', async () => {
  ui.logStep('07 DISABLE MASTER AUTHORISATION');
  const gate = evaluateGate(GATE.DISABLE_MASTER, state);
  if (!gate.open) throw new Error('Disable-master gate is not satisfied.');

  const link = await ensureLink();

  // Final re-read. Between proving control and this moment the account could have
  // changed; nothing here trusts a value older than this scan.
  const fresh = await scanAccount(link, state.scan.address, state.networkStatus);
  if (fresh.regularKey !== state.newAuthority.address) {
    throw new Error(`RegularKey changed to "${fresh.regularKey || 'NONE'}" — aborting.`);
  }
  if (!fresh.masterKeyActive) {
    ui.log('Master key is already disabled. Nothing to submit.', 'warn');
    state.proofScan = fresh;
    completeStage(6, 7);
    await doFinalAudit();
    return;
  }
  state.proofScan = fresh;

  const transaction = {
    TransactionType: 'AccountSet',
    Account: fresh.address,
    SetFlag: ASF_DISABLE_MASTER,
  };

  ui.log('Submitting AccountSet · asfDisableMaster, signed by the master key...', 'info');
  const result = await link.signAndSubmit(transaction, state.masterWallet);
  state.disableTx = result;
  recordReceipt('DISABLE MASTER', result);
  ui.log(`Disable result: ${result.engineResult} (${result.hash})`, resultTone(result));

  if (result.engineResult !== 'tesSUCCESS') {
    const hint =
      result.engineResult === 'tecNEED_MASTER_KEY'
        ? ' asfDisableMaster must be signed by the master key pair, not a regular key.'
        : result.engineResult === 'tecNO_ALTERNATIVE_KEY'
          ? ' The ledger sees no alternative signing method on this account.'
          : '';
    ui.renderNotices('p7-notices', [
      { level: 'error', text: `Rejected: ${result.engineResult}.${hint} The master key is still enabled.` },
    ]);
    throw new Error(`asfDisableMaster failed: ${result.engineResult}`);
  }

  completeStage(6, 7);
  await doFinalAudit();
});

/* ------------------------------------------------------------------ *
 * 08 FINAL AUDIT
 * ------------------------------------------------------------------ */

const doRescan = guard('btn-rescan', () => doFinalAudit());

async function doFinalAudit() {
  ui.logStep('08 FINAL AUDIT');
  const link = await ensureLink();
  const scan = await scanAccount(link, state.scan.address, state.networkStatus);
  state.finalScan = scan;

  const keyVerified = scan.regularKey === state.newAuthority.address;
  const masterDisabled = scan.masterKeyActive === false;
  const complete = keyVerified && masterDisabled && state.controlProof?.proven === true;

  const report = [
    'XRPMAN SECURITY AUDIT',
    '',
    'ACCOUNT',
    scan.address,
    '',
    'NETWORK',
    link.network.label,
    '',
    'REGULAR KEY',
    scan.regularKey || 'NONE',
    '',
    'REGULAR KEY VERIFIED',
    keyVerified ? 'YES' : 'NO',
    '',
    'MASTER AUTHORIZATION',
    masterDisabled ? 'DISABLED' : 'ACTIVE',
    '',
    'NEW AUTHORITY CONTROL',
    state.controlProof?.proven ? 'PROVEN' : 'UNPROVEN',
    '',
    'SIGNER LIST',
    scan.signerList ? `${scan.signerList.entries.length} SIGNERS · QUORUM ${scan.signerList.quorum}` : 'NONE',
    '',
    'BALANCE',
    `${scan.balanceXrp} XRP`,
    '',
    'SEQUENCE',
    String(scan.sequence ?? '—'),
    '',
    'LEDGER',
    `${scan.ledgerIndex} VALIDATED`,
    '',
    'AUDITED AT',
    scan.scannedAt,
    '',
    'STATUS',
    complete ? 'REKEY COMPLETE' : 'INCOMPLETE — SEE TELEMETRY',
  ].join('\n');

  ui.renderAudit('p8-report', report);
  ui.renderTransactions(
    'p8-transactions',
    receipts.map((receipt) => ({ ...receipt, explorer: link.explorerLink(receipt.hash) })),
  );
  ui.renderNotices('p8-notices', [
    {
      level: complete ? 'info' : 'warn',
      text: complete
        ? 'Rekey complete. Verify every hash above on an independent explorer before discarding this tab.'
        : 'The procedure did not reach a complete state. Nothing below the last successful step was applied.',
    },
  ]);

  ui.setChip('chip-account', shortAddress(scan.address), complete ? 'ok' : 'warn');
  ui.log(complete ? 'REKEY COMPLETE.' : 'Audit finished — procedure incomplete.', complete ? 'success' : 'warn');
  if (complete) state.completed.add(7);
  setStage(7);
  ui.setText('p8-status', complete ? 'COMPLETE' : 'INCOMPLETE');
}

const doCopyAudit = guard('btn-copy-audit', async () => {
  const text = ui.$('p8-report').textContent;
  await navigator.clipboard.writeText(text);
  ui.log('Audit report copied. It contains no private key material.', 'success');
});

/* ------------------------------------------------------------------ *
 * Gates → UI
 * ------------------------------------------------------------------ */

function refreshGates() {
  if (state.scan && state.newAuthority) {
    const rekey = evaluateGate(GATE.REKEY, state);
    ui.renderChecklist('p4-gate', rekey.checks);
    ui.setDisabled('btn-rekey', !rekey.open || state.busy);
  }
  if (state.verifyScan) {
    const prove = evaluateGate(GATE.PROVE, state);
    ui.renderChecklist('p6-gate', prove.checks);
    ui.setDisabled('btn-prove', !prove.open || state.busy);
  }
  if (state.proofScan) {
    const disable = evaluateGate(GATE.DISABLE_MASTER, state);
    ui.renderChecklist('p7-gate', disable.checks);
    ui.setDisabled('btn-disable', !disable.open || state.busy);
  }
}

/* ------------------------------------------------------------------ *
 * Helpers
 * ------------------------------------------------------------------ */

function recordReceipt(label, result) {
  receipts.push({
    label,
    hash: result.hash,
    result: result.engineResult,
    ledgerIndex: result.ledgerIndex,
  });
}

function resultTone(result) {
  return result.engineResult === 'tesSUCCESS' ? 'success' : 'error';
}

function shortAddress(address) {
  return address ? `${address.slice(0, 6)}…${address.slice(-4)}` : 'NONE';
}

/* ------------------------------------------------------------------ *
 * Wiring
 * ------------------------------------------------------------------ */

function selectNetwork(networkId) {
  const network = NETWORKS[networkId];
  if (!network || network.gated) {
    ui.log(`${network?.label || networkId} is gated in this build — see README, Phase 11.`, 'warn');
    return;
  }
  state.networkId = networkId;
  for (const id of Object.keys(NETWORKS)) {
    const button = ui.$(`net-${id}`);
    if (button) button.setAttribute('aria-pressed', String(id === networkId));
  }
  ui.setChip('chip-network', network.label, 'idle');
  ui.log(`Network set to ${network.label}.`, 'info');
}

function selectInputMode(mode) {
  state.inputMode = mode;
  ui.$('mode-secret').setAttribute('aria-pressed', String(mode === 'secret'));
  ui.$('mode-watch').setAttribute('aria-pressed', String(mode === 'watch'));
  ui.setHidden('input-secret', mode !== 'secret');
  ui.setHidden('input-watch', mode !== 'watch');
}

function selectAuthorityMode(mode) {
  state.authorityMode = mode;
  ui.$('auth-generate').setAttribute('aria-pressed', String(mode === 'generate'));
  ui.$('auth-existing').setAttribute('aria-pressed', String(mode === 'existing'));
  ui.setHidden('auth-generate-panel', mode !== 'generate');
  ui.setHidden('auth-existing-panel', mode !== 'existing');
}

function resetSession() {
  for (const id of ['src-secret', 'src-address', 'auth-address', 'auth-secret', 'backup-confirm', 'disable-phrase']) {
    wipeInput(ui.$(id));
  }
  if (state.link) state.link.disconnect();
  window.location.reload();
}

function bind() {
  for (const id of Object.keys(NETWORKS)) {
    const button = ui.$(`net-${id}`);
    if (button) button.addEventListener('click', () => selectNetwork(id));
  }
  ui.$('mode-secret').addEventListener('click', () => selectInputMode('secret'));
  ui.$('mode-watch').addEventListener('click', () => selectInputMode('watch'));
  ui.$('auth-generate').addEventListener('click', () => selectAuthorityMode('generate'));
  ui.$('auth-existing').addEventListener('click', () => selectAuthorityMode('existing'));

  ui.$('btn-scan').addEventListener('click', doScan);
  ui.$('btn-generate').addEventListener('click', doGenerate);
  ui.$('btn-use-existing').addEventListener('click', doUseExisting);
  ui.$('btn-lock-authority').addEventListener('click', doLockAuthority);
  ui.$('btn-rekey').addEventListener('click', doRekey);
  ui.$('btn-verify').addEventListener('click', doVerify);
  ui.$('btn-load-authority').addEventListener('click', doLoadAuthoritySecret);
  ui.$('btn-prove').addEventListener('click', doProve);
  ui.$('btn-disable').addEventListener('click', doDisable);
  ui.$('btn-rescan').addEventListener('click', doRescan);
  ui.$('btn-copy-audit').addEventListener('click', doCopyAudit);
  ui.$('btn-reset').addEventListener('click', resetSession);

  ui.$('backup-confirm').addEventListener('input', evaluateBackup);
  ui.$('chk-backup').addEventListener('change', evaluateBackup);
  ui.$('chk-disable').addEventListener('change', evaluateDisableAck);
  ui.$('disable-phrase').addEventListener('input', evaluateDisableAck);

  // Nothing survives a reload by design, so a half-finished procedure must not be
  // navigated away from silently.
  window.addEventListener('beforeunload', (event) => {
    if (state.masterWallet && !state.completed.has(7)) {
      event.preventDefault();
      event.returnValue = '';
    }
  });
}

function boot() {
  bind();
  // Seed every chip through setChip so the labels render before the first update,
  // rather than showing a bare value until something happens to refresh them.
  ui.setChip('chip-network', 'OFFLINE', 'idle');
  ui.setChip('chip-ledger', '—', 'idle');
  ui.setChip('chip-account', 'NONE', 'idle');
  selectNetwork(DEFAULT_NETWORK);
  selectInputMode('secret');
  selectAuthorityMode('generate');
  setStage(0);

  ui.log('XRPMAN REKEY V8 ready.', 'success');
  ui.log('SCAN → UNDERSTAND → REKEY → VERIFY → PROVE → LOCK → AUDIT', 'step');
  if (!MAINNET_ENABLED) {
    ui.log('Mainnet is gated in this build. Testnet and Devnet only.', 'warn');
  }
  ui.log('No secret is written to storage, URLs, logs, or network requests.', 'info');
}

boot();
