/**
 * XRPMAN REKEY V8 — security.js
 * Account interrogation and the gates that stand between the operator and an
 * irreversible transaction.
 *
 * The whole point of V8 lives here: V7 disabled the master key on the strength of
 * an in-memory boolean set by a `tesSUCCESS` string (audit F4/F5). Every gate below
 * is evaluated against a freshly scanned validated ledger, and nothing in this module
 * can be satisfied by a submit result alone.
 */

import { dropsToXrp } from './xrpl.js';

/* ------------------------------------------------------------------ *
 * Ledger flags
 * ------------------------------------------------------------------ */

export const LSF = Object.freeze({
  PASSWORD_SPENT: 0x00010000,
  REQUIRE_DEST_TAG: 0x00020000,
  REQUIRE_AUTH: 0x00040000,
  DISALLOW_XRP: 0x00080000,
  DISABLE_MASTER: 0x00100000,
  NO_FREEZE: 0x00200000,
  GLOBAL_FREEZE: 0x00400000,
  DEFAULT_RIPPLE: 0x00800000,
  DEPOSIT_AUTH: 0x01000000,
});

/** AccountSet SetFlag value for asfDisableMaster. Preserved from V7, which had it right. */
export const ASF_DISABLE_MASTER = 4;

export function decodeAccountFlags(flags) {
  const raw = Number(flags || 0);
  return {
    raw,
    passwordSpent: Boolean(raw & LSF.PASSWORD_SPENT),
    requireDestTag: Boolean(raw & LSF.REQUIRE_DEST_TAG),
    requireAuth: Boolean(raw & LSF.REQUIRE_AUTH),
    disallowXrp: Boolean(raw & LSF.DISALLOW_XRP),
    disableMaster: Boolean(raw & LSF.DISABLE_MASTER),
    noFreeze: Boolean(raw & LSF.NO_FREEZE),
    globalFreeze: Boolean(raw & LSF.GLOBAL_FREEZE),
    defaultRipple: Boolean(raw & LSF.DEFAULT_RIPPLE),
    depositAuth: Boolean(raw & LSF.DEPOSIT_AUTH),
  };
}

/* ------------------------------------------------------------------ *
 * Scanner
 * ------------------------------------------------------------------ */

/**
 * Reads the account's actual security posture from a validated ledger.
 * Runs before the wizard offers any action, and again after every transaction.
 */
export async function scanAccount(link, address, networkStatus) {
  const info = await link.accountInfo(address);

  if (!info.exists) {
    return {
      address,
      exists: false,
      scannedAt: new Date().toISOString(),
      ledgerIndex: null,
      validated: true,
      network: link.network.label,
      endpoint: link.endpoint,
      balanceDrops: '0',
      balanceXrp: '0.000000',
      sequence: null,
      ownerCount: 0,
      reserveXrp: null,
      spendableXrp: null,
      flags: decodeAccountFlags(0),
      masterKeyActive: null,
      regularKey: null,
      signerList: null,
    };
  }

  const data = info.data;
  const flags = decodeAccountFlags(data.Flags);
  const ownerCount = Number(data.OwnerCount || 0);
  const reserveXrp = computeReserve(ownerCount, networkStatus);
  const balanceXrp = Number(dropsToXrp(data.Balance));

  const signerLists = info.signerLists || [];
  const signerList = signerLists.length
    ? {
        quorum: Number(signerLists[0].SignerQuorum || 0),
        entries: (signerLists[0].SignerEntries || []).map((e) => ({
          account: e.SignerEntry.Account,
          weight: Number(e.SignerEntry.SignerWeight || 0),
        })),
      }
    : null;

  return {
    address,
    exists: true,
    scannedAt: new Date().toISOString(),
    ledgerIndex: info.ledgerIndex,
    validated: info.validated,
    network: link.network.label,
    endpoint: link.endpoint,
    balanceDrops: String(data.Balance),
    balanceXrp: dropsToXrp(data.Balance),
    sequence: Number(data.Sequence),
    ownerCount,
    reserveXrp,
    spendableXrp: reserveXrp === null ? null : Math.max(0, balanceXrp - reserveXrp).toFixed(6),
    flags,
    masterKeyActive: !flags.disableMaster,
    regularKey: data.RegularKey || null,
    signerList,
  };
}

function computeReserve(ownerCount, networkStatus) {
  const base = networkStatus?.reserveBaseXrp;
  const inc = networkStatus?.reserveIncXrp;
  if (typeof base !== 'number' || typeof inc !== 'number') return null;
  return base + inc * ownerCount;
}

/**
 * Human-readable posture summary. Used by the HUD and the final audit so that both
 * describe the account in the same words.
 */
export function describePosture(scan) {
  if (!scan) return 'NOT SCANNED';
  if (!scan.exists) return 'ACCOUNT NOT FOUND ON LEDGER';

  const parts = [];
  parts.push(scan.masterKeyActive ? 'MASTER ACTIVE' : 'MASTER DISABLED');
  parts.push(scan.regularKey ? 'REGULAR KEY SET' : 'NO REGULAR KEY');
  if (scan.signerList) parts.push(`SIGNER LIST ${scan.signerList.entries.length}/${scan.signerList.quorum}`);
  return parts.join(' // ');
}

/**
 * Conditions that make an account unsafe or impossible to rekey, surfaced before
 * the operator commits to anything. V7 scanned for none of these (audit F12).
 */
export function preflightWarnings(scan, networkStatus) {
  const warnings = [];

  if (!scan.exists) {
    warnings.push({
      level: 'error',
      text: 'Account does not exist on this network. It is unfunded, or you are on the wrong network.',
    });
    return warnings;
  }

  if (!scan.masterKeyActive) {
    warnings.push({
      level: 'error',
      text: 'Master key is already disabled. This account cannot sign a rekey with its master key.',
    });
  }

  if (scan.regularKey) {
    warnings.push({
      level: 'warn',
      text: `A regular key is already set (${scan.regularKey}). Continuing REPLACES it.`,
    });
  }

  if (scan.signerList) {
    warnings.push({
      level: 'warn',
      text: `Signer list present: ${scan.signerList.entries.length} signers, quorum ${scan.signerList.quorum}. Multisig authority is unaffected by this wizard.`,
    });
  }

  if (scan.spendableXrp !== null && Number(scan.spendableXrp) <= 0) {
    warnings.push({
      level: 'error',
      text: `Balance ${scan.balanceXrp} XRP is at or below the ${scan.reserveXrp} XRP reserve. No fee can be paid.`,
    });
  }

  if (scan.flags.globalFreeze) {
    warnings.push({ level: 'warn', text: 'Global freeze is set on this account.' });
  }

  if (networkStatus?.mismatch) {
    warnings.push({
      level: 'error',
      text: `Network mismatch: endpoint reports network_id ${networkStatus.reportedNetworkId}, expected ${networkStatus.expectedNetworkId}.`,
    });
  }

  if (networkStatus?.stale) {
    warnings.push({
      level: 'warn',
      text: `Validated ledger is ${networkStatus.ledgerAge}s old. The node may be lagging.`,
    });
  }

  return warnings;
}

/* ------------------------------------------------------------------ *
 * Gates
 *
 * Each gate is a list of requirements evaluated against live state. A gate opens
 * only when every requirement is true. There is no override parameter, and nothing
 * calls these with a "force" flag — by design, because that is the button that
 * would eventually get pressed.
 * ------------------------------------------------------------------ */

export const GATE = Object.freeze({
  REKEY: 'REKEY',
  PROVE: 'PROVE',
  DISABLE_MASTER: 'DISABLE_MASTER',
});

const REQUIREMENTS = {
  [GATE.REKEY]: [
    {
      id: 'source-scanned',
      label: 'SOURCE ACCOUNT SCANNED ON VALIDATED LEDGER',
      test: (c) => Boolean(c.scan?.exists && c.scan.validated),
    },
    {
      id: 'master-active',
      label: 'MASTER KEY ACTIVE',
      test: (c) => c.scan?.masterKeyActive === true,
    },
    {
      id: 'master-held',
      label: 'MASTER SECRET LOADED AND ADDRESS CONFIRMED',
      test: (c) => Boolean(c.masterWallet && c.masterWallet.address === c.scan?.address),
    },
    {
      id: 'authority-chosen',
      label: 'NEW AUTHORITY ADDRESS SELECTED',
      test: (c) => Boolean(c.newAuthority?.address),
    },
    {
      id: 'authority-distinct',
      label: 'NEW AUTHORITY DIFFERS FROM ACCOUNT',
      test: (c) => Boolean(c.newAuthority?.address) && c.newAuthority.address !== c.scan?.address,
    },
    {
      id: 'backup-saved',
      label: 'RECOVERY CREDENTIALS SAVED AND RE-ENTERED',
      test: (c) => c.backupConfirmed === true,
    },
    {
      id: 'network-ok',
      label: 'NETWORK CONFIRMED, NO MISMATCH',
      test: (c) => c.networkStatus != null && c.networkStatus.mismatch === false,
    },
  ],

  [GATE.PROVE]: [
    {
      id: 'regular-key-on-ledger',
      label: 'REGULARKEY PRESENT ON VALIDATED LEDGER',
      test: (c) => Boolean(c.verifyScan?.regularKey),
    },
    {
      id: 'regular-key-match',
      label: 'LEDGER REGULARKEY MATCHES EXPECTED ADDRESS',
      test: (c) =>
        Boolean(c.verifyScan?.regularKey) && c.verifyScan.regularKey === c.newAuthority?.address,
    },
    {
      id: 'authority-secret',
      label: 'NEW AUTHORITY SECRET AVAILABLE FOR SIGNING',
      test: (c) => Boolean(c.authorityWallet),
    },
    {
      id: 'authority-derives',
      label: 'AUTHORITY SECRET DERIVES THE LEDGER REGULARKEY',
      test: (c) =>
        Boolean(c.authorityWallet) && c.authorityWallet.address === c.verifyScan?.regularKey,
    },
  ],

  [GATE.DISABLE_MASTER]: [
    {
      id: 'regular-key-on-ledger',
      label: 'REGULARKEY EXISTS ON VALIDATED LEDGER',
      test: (c) =>
        Boolean(c.proofScan?.regularKey) && c.proofScan.regularKey === c.newAuthority?.address,
    },
    {
      id: 'control-proven',
      label: 'NEW AUTHORITY CONTROL PROVEN BY VALIDATED TRANSACTION',
      test: (c) => c.controlProof?.proven === true,
    },
    {
      id: 'credentials-saved',
      label: 'RECOVERY CREDENTIALS SAVED',
      test: (c) => c.backupConfirmed === true,
    },
    {
      id: 'network-confirmed',
      label: 'CORRECT NETWORK CONFIRMED',
      test: (c) =>
        c.networkStatus != null &&
        c.networkStatus.mismatch === false &&
        c.disableAcknowledged === true,
    },
    {
      id: 'master-still-active',
      label: 'MASTER KEY STILL ACTIVE (NOTHING TO DO OTHERWISE)',
      test: (c) => c.proofScan?.masterKeyActive === true,
    },
    {
      id: 'master-signer',
      label: 'MASTER SECRET AVAILABLE — asfDisableMaster REQUIRES IT',
      test: (c) => Boolean(c.masterWallet && c.masterWallet.address === c.proofScan?.address),
    },
  ],
};

export function evaluateGate(gate, context) {
  const requirements = REQUIREMENTS[gate];
  if (!requirements) throw new Error(`Unknown gate "${gate}"`);
  const checks = requirements.map((r) => ({
    id: r.id,
    label: r.label,
    ok: Boolean(safeTest(r.test, context)),
  }));
  return { gate, checks, open: checks.every((c) => c.ok) };
}

function safeTest(test, context) {
  try {
    return test(context);
  } catch {
    return false;
  }
}

/**
 * Confirms a replacement credential is genuinely usable: the ledger holds the
 * expected RegularKey, and a transaction signed by that key was accepted and
 * validated. Both halves are required — a matching RegularKey field only proves
 * the SetRegularKey landed, not that anyone holds the corresponding secret.
 */
export function assessControlProof({ scan, expectedAddress, proofTx, authorityWallet }) {
  const derivedMatch = Boolean(authorityWallet && authorityWallet.address === expectedAddress);
  const ledgerMatch = Boolean(scan?.regularKey && scan.regularKey === expectedAddress);
  const signatureValid = proofTx?.engineResult === 'tesSUCCESS';
  const txValidated = proofTx?.validated === true;

  return {
    derivedMatch,
    ledgerMatch,
    signatureValid,
    txValidated,
    hash: proofTx?.hash || null,
    proven: derivedMatch && ledgerMatch && signatureValid && txValidated,
  };
}
