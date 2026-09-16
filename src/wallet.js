/**
 * XRPMAN REKEY V8 — wallet.js
 * Key material: parsing, derivation, generation, disposal.
 *
 * Rules enforced in this module:
 *   - Every representation accepted here is standards-compliant and provably reversible.
 *     V7's "Universal Safe Key" formats are gone; see docs/V7-AUDIT.md F1/F2/F3.
 *   - Entropy-based inputs are algorithm-ambiguous (audit F14), so this module never guesses.
 *     It returns every candidate and lets the ledger scan resolve which account is real.
 *   - Nothing here writes to storage, the DOM, the console, or the network.
 */

const xrpl = globalThis.xrpl;
if (!xrpl) throw new Error('xrpl runtime not loaded');

const { Wallet, ECDSA } = xrpl;

export const ALGORITHMS = Object.freeze({
  SECP256K1: ECDSA.secp256k1,
  ED25519: ECDSA.ed25519,
});

export const ALGORITHM_LABEL = Object.freeze({
  [ECDSA.secp256k1]: 'SECP256K1',
  [ECDSA.ed25519]: 'ED25519',
});

/** XRPL BIP39 account derivation path used by xrpl.js. */
export const DEFAULT_DERIVATION_PATH = "m/44'/144'/0'/0/0";

/* ------------------------------------------------------------------ *
 * Address validation
 * ------------------------------------------------------------------ */

export function isValidAddress(value) {
  return typeof value === 'string' && xrpl.isValidClassicAddress(value.trim());
}

/**
 * The account's own address is never a legal RegularKey — rippled rejects it with
 * temBAD_REGKEY, and an operator who set it would believe they had a second credential
 * when they only ever had the master key.
 */
export function assertUsableRegularKey(regularKey, accountAddress) {
  if (!isValidAddress(regularKey)) {
    throw new Error('Regular key is not a valid XRPL classic address');
  }
  if (regularKey === accountAddress) {
    throw new Error('Regular key cannot equal the account address (temBAD_REGKEY)');
  }
}

/* ------------------------------------------------------------------ *
 * XRPL Secret Numbers
 *
 * The real standard, not V7's lossy imitation: 8 groups of 6 digits, where digits
 * 0-4 hold a uint16 (00000-65535) and digit 5 is a checksum, value*(pos*2+1)%9.
 * The eight uint16s concatenate big-endian into exactly 16 bytes of entropy.
 * Verified byte-for-byte against xrpl-secret-numbers@0.3.5.
 * ------------------------------------------------------------------ */

export function calculateChecksum(position, value) {
  return (value * (position * 2 + 1)) % 9;
}

export function splitSecretNumberString(input) {
  const digits = String(input).replace(/[^0-9]/g, '');
  if (digits.length !== 48) {
    throw new Error(
      `Secret numbers must be 8 blocks of 6 digits (48 total); received ${digits.length}`,
    );
  }
  return Array.from({ length: 8 }, (_, i) => digits.slice(i * 6, i * 6 + 6));
}

export function secretNumbersToEntropy(groups) {
  const list = Array.isArray(groups) ? groups : splitSecretNumberString(groups);
  if (list.length !== 8) throw new Error('Secret numbers must contain exactly 8 blocks');

  const entropy = new Uint8Array(16);
  list.forEach((raw, position) => {
    const block = String(raw).trim();
    if (!/^\d{6}$/.test(block)) {
      throw new Error(`Block ${blockLabel(position)} is not 6 digits`);
    }
    const value = Number(block.slice(0, 5));
    const checksum = Number(block.slice(5));
    if (value > 0xffff) {
      throw new Error(`Block ${blockLabel(position)} exceeds the 65535 maximum`);
    }
    if (calculateChecksum(position, value) !== checksum) {
      throw new Error(`Block ${blockLabel(position)} failed its checksum digit`);
    }
    entropy[position * 2] = (value >> 8) & 0xff;
    entropy[position * 2 + 1] = value & 0xff;
  });
  return entropy;
}

export function entropyToSecretNumbers(entropy) {
  if (!(entropy instanceof Uint8Array) || entropy.length !== 16) {
    throw new Error('Secret numbers require exactly 16 bytes of entropy');
  }
  return Array.from({ length: 8 }, (_, position) => {
    const value = (entropy[position * 2] << 8) | entropy[position * 2 + 1];
    return String(value).padStart(5, '0') + String(calculateChecksum(position, value));
  });
}

export function blockLabel(index) {
  return String.fromCharCode(65 + index);
}

/* ------------------------------------------------------------------ *
 * Input classification
 * ------------------------------------------------------------------ */

export const INPUT_KIND = Object.freeze({
  FAMILY_SEED: 'FAMILY SEED',
  SECRET_NUMBERS: 'SECRET NUMBERS',
  MNEMONIC: 'BIP39 MNEMONIC',
  HEX_ENTROPY: 'HEX ENTROPY',
  UNKNOWN: 'UNRECOGNISED',
});

export function classifySecret(raw) {
  const value = String(raw || '').trim();
  if (!value) return INPUT_KIND.UNKNOWN;
  if (/^s[1-9A-HJ-NP-Za-km-z]{24,}$/.test(value)) return INPUT_KIND.FAMILY_SEED;
  if (value.replace(/[^0-9]/g, '').length === 48 && !/[a-zA-Z]/.test(value)) {
    return INPUT_KIND.SECRET_NUMBERS;
  }
  if (/^[0-9a-fA-F]{32}$/.test(value)) return INPUT_KIND.HEX_ENTROPY;
  if (value.split(/\s+/).length >= 12) return INPUT_KIND.MNEMONIC;
  return INPUT_KIND.UNKNOWN;
}

function hexToEntropy(hex) {
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i += 1) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}

/* ------------------------------------------------------------------ *
 * Derivation
 *
 * Returns *candidates*. A family seed encodes its own algorithm and yields exactly
 * one; raw entropy yields two, and only the ledger can say which account is real.
 * ------------------------------------------------------------------ */

export function deriveCandidates(raw) {
  const value = String(raw || '').trim();
  const kind = classifySecret(value);

  switch (kind) {
    case INPUT_KIND.FAMILY_SEED: {
      const wallet = Wallet.fromSeed(value);
      return { kind, candidates: [candidate(wallet, seedAlgorithm(value), 'encoded in seed prefix')] };
    }

    case INPUT_KIND.SECRET_NUMBERS: {
      const entropy = secretNumbersToEntropy(value);
      return { kind, candidates: entropyCandidates(entropy) };
    }

    case INPUT_KIND.HEX_ENTROPY: {
      const entropy = hexToEntropy(value);
      return { kind, candidates: entropyCandidates(entropy) };
    }

    case INPUT_KIND.MNEMONIC: {
      // xrpl.js ignores `algorithm` for bip39 — it derives a secp256k1 key over
      // BIP32 at m/44'/144'/0'/0/0, so there is exactly one candidate.
      const wallet = Wallet.fromMnemonic(value, {
        mnemonicEncoding: 'bip39',
        derivationPath: DEFAULT_DERIVATION_PATH,
      });
      return {
        kind,
        candidates: [candidate(wallet, ALGORITHMS.SECP256K1, `bip39 ${DEFAULT_DERIVATION_PATH}`)],
      };
    }

    default:
      throw new Error(
        'Unrecognised secret format. Accepted: family seed (s...), 8x6 secret numbers, ' +
          'BIP39 mnemonic, or 32 hex characters of entropy.',
      );
  }
}

function entropyCandidates(entropy) {
  return [ALGORITHMS.SECP256K1, ALGORITHMS.ED25519].map((algorithm) =>
    candidate(Wallet.fromEntropy(entropy, { algorithm }), algorithm, 'ambiguous — resolve on ledger'),
  );
}

function candidate(wallet, algorithm, note) {
  return { wallet, address: wallet.address, algorithm, note };
}

function seedAlgorithm(seed) {
  return seed.startsWith('sEd') ? ALGORITHMS.ED25519 : ALGORITHMS.SECP256K1;
}

/* ------------------------------------------------------------------ *
 * Generation
 * ------------------------------------------------------------------ */

/**
 * A fresh authority, generated locally. Secret numbers are emitted only for
 * secp256k1, because the Secret Numbers standard defines a 16-byte family-seed
 * entropy and Xaman restores it as secp256k1. Emitting them beside an ed25519
 * seed would produce a backup that restores a different account.
 */
export function generateAuthority(algorithm = ALGORITHMS.SECP256K1) {
  const entropy = crypto.getRandomValues(new Uint8Array(16));
  try {
    const wallet = Wallet.fromEntropy(entropy, { algorithm });
    return {
      wallet,
      address: wallet.address,
      seed: wallet.seed,
      publicKey: wallet.publicKey,
      algorithm,
      secretNumbers:
        algorithm === ALGORITHMS.SECP256K1 ? entropyToSecretNumbers(entropy) : null,
    };
  } finally {
    entropy.fill(0);
  }
}

/* ------------------------------------------------------------------ *
 * Disposal
 * ------------------------------------------------------------------ */

/**
 * Best-effort erasure of key material held in DOM inputs and plain strings.
 * JavaScript cannot guarantee a string is gone from memory, so the real defence
 * is never persisting it: no storage, no URLs, no network, no logs.
 */
export function wipeInput(element) {
  if (!element) return;
  try {
    element.value = '0'.repeat(String(element.value || '').length);
    element.value = '';
  } catch {
    /* element may be detached */
  }
}

export function wipeAll(elements) {
  for (const element of elements) wipeInput(element);
}
