/**
 * XRPMAN REKEY V8 — xrpl.js
 * Ledger transport. Every read in this file is pinned to a validated ledger.
 *
 * V7 read whatever the node felt like returning and trusted a submit result as
 * proof of state (audit F4). Nothing here reports a fact that has not been
 * confirmed against `ledger_index: 'validated'`.
 */

const xrpl = globalThis.xrpl;
if (!xrpl) throw new Error('xrpl runtime not loaded');

/**
 * Mainnet endpoints are declared but gated — see MAINNET_ENABLED. Declaring them
 * keeps the release sequence in Phase 11 a one-line change rather than a rewrite.
 */
export const MAINNET_ENABLED = false;

export const NETWORKS = Object.freeze({
  testnet: {
    id: 'testnet',
    label: 'TESTNET',
    networkId: 1,
    gated: false,
    explorer: 'https://testnet.xrpl.org/transactions/',
    endpoints: ['wss://s.altnet.rippletest.net:51233'],
  },
  devnet: {
    id: 'devnet',
    label: 'DEVNET',
    networkId: 2,
    gated: false,
    explorer: 'https://devnet.xrpl.org/transactions/',
    endpoints: ['wss://s.devnet.rippletest.net:51233'],
  },
  mainnet: {
    id: 'mainnet',
    label: 'MAINNET',
    networkId: 0,
    gated: !MAINNET_ENABLED,
    explorer: 'https://livenet.xrpl.org/transactions/',
    endpoints: ['wss://xrplcluster.com', 'wss://s1.ripple.com', 'wss://s2.ripple.com'],
  },
});

export const DEFAULT_NETWORK = 'testnet';

/** A validated ledger older than this is treated as stale and surfaced to the operator. */
export const STALE_LEDGER_SECONDS = 60;

const CONNECT_TIMEOUT_MS = 12_000;

export class LedgerError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'LedgerError';
    this.code = code || 'LEDGER_ERROR';
  }
}

/**
 * A connection to one network, with failover across that network's endpoints.
 * Callers get one object for the whole wizard; it reconnects on demand.
 */
export class LedgerLink {
  constructor(networkId) {
    const network = NETWORKS[networkId];
    if (!network) throw new LedgerError(`Unknown network "${networkId}"`, 'UNKNOWN_NETWORK');
    if (network.gated) {
      throw new LedgerError(`${network.label} is gated in this build`, 'NETWORK_GATED');
    }
    this.network = network;
    this.client = null;
    this.endpoint = null;
  }

  get connected() {
    return Boolean(this.client && this.client.isConnected());
  }

  async connect(onAttempt) {
    if (this.connected) return this.endpoint;
    const failures = [];

    for (const url of this.network.endpoints) {
      if (onAttempt) onAttempt(url);
      const client = new xrpl.Client(url, { connectionTimeout: CONNECT_TIMEOUT_MS });
      try {
        await client.connect();
        this.client = client;
        this.endpoint = url;
        return url;
      } catch (error) {
        failures.push(`${url} (${error.message || error})`);
        try {
          await client.disconnect();
        } catch {
          /* already down */
        }
      }
    }

    throw new LedgerError(
      `No ${this.network.label} endpoint reachable. Tried: ${failures.join('; ')}`,
      'RPC_UNREACHABLE',
    );
  }

  async disconnect() {
    if (!this.client) return;
    try {
      await this.client.disconnect();
    } catch {
      /* already down */
    }
    this.client = null;
    this.endpoint = null;
  }

  async request(payload) {
    if (!this.connected) await this.connect();
    return this.client.request(payload);
  }

  /**
   * Confirms the node we reached actually serves the network the operator selected.
   * Connecting to a testnet URL is not proof of being on testnet — a misconfigured
   * proxy or a repointed hostname is exactly the failure this catches.
   */
  async verifyNetwork() {
    const response = await this.request({ command: 'server_info' });
    const info = response.result.info;
    const reported = info.network_id;
    const validated = info.validated_ledger || {};

    const result = {
      endpoint: this.endpoint,
      expectedNetworkId: this.network.networkId,
      reportedNetworkId: typeof reported === 'number' ? reported : null,
      buildVersion: info.build_version || null,
      serverState: info.server_state || null,
      ledgerIndex: validated.seq ?? null,
      ledgerAge: typeof validated.age === 'number' ? validated.age : null,
      reserveBaseXrp: validated.reserve_base_xrp ?? null,
      reserveIncXrp: validated.reserve_inc_xrp ?? null,
      stale: false,
      mismatch: false,
    };

    // Mainnet omits network_id on many builds; absence is not evidence of mismatch.
    if (result.reportedNetworkId !== null) {
      result.mismatch = result.reportedNetworkId !== this.network.networkId;
    }
    result.stale = result.ledgerAge !== null && result.ledgerAge > STALE_LEDGER_SECONDS;
    return result;
  }

  async validatedLedgerIndex() {
    const response = await this.request({ command: 'ledger', ledger_index: 'validated' });
    return response.result.ledger_index;
  }

  /**
   * Validated-ledger account state. Returns null when the account is not funded,
   * which is a legitimate answer rather than an error the caller has to parse.
   */
  async accountInfo(address) {
    try {
      const response = await this.request({
        command: 'account_info',
        account: address,
        ledger_index: 'validated',
        signer_lists: true,
      });
      return {
        exists: true,
        data: response.result.account_data,
        // rippled API v2 returns signer_lists at the result root; v1 nests it under
        // account_data. xrpl.js 5.x negotiates v2, so read the root first.
        signerLists:
          response.result.signer_lists || response.result.account_data.signer_lists || [],
        ledgerIndex: response.result.ledger_index,
        validated: response.result.validated === true,
      };
    } catch (error) {
      if (isAccountNotFound(error)) {
        return { exists: false, data: null, signerLists: [], ledgerIndex: null, validated: true };
      }
      throw error;
    }
  }

  async accountObjects(address, type) {
    const response = await this.request({
      command: 'account_objects',
      account: address,
      ledger_index: 'validated',
      ...(type ? { type } : {}),
    });
    return response.result.account_objects || [];
  }

  /**
   * autofill + local sign + submitAndWait. The signing wallet need not own the
   * Account field — that is precisely how a regular key authorises a transaction,
   * and how Phase 06 proves the replacement credential works.
   */
  async signAndSubmit(transaction, wallet) {
    if (!this.connected) await this.connect();
    const prepared = await this.client.autofill({ ...transaction });
    const signed = wallet.sign(prepared);
    const response = await this.client.submitAndWait(signed.tx_blob, { failHard: false });
    const meta = response.result.meta || {};

    return {
      hash: response.result.hash || signed.hash,
      engineResult: typeof meta === 'object' ? meta.TransactionResult : String(meta),
      validated: response.result.validated === true,
      ledgerIndex: response.result.ledger_index ?? null,
      sequence: prepared.Sequence ?? null,
      fee: prepared.Fee ?? null,
      signingPubKey: wallet.publicKey,
      raw: response.result,
    };
  }

  /** Independent re-read of a transaction, so success is confirmed by lookup, not by the submit reply. */
  async transaction(hash) {
    const response = await this.request({ command: 'tx', transaction: hash, binary: false });
    const meta = response.result.meta || response.result.metaData || {};
    return {
      hash,
      validated: response.result.validated === true,
      engineResult: typeof meta === 'object' ? meta.TransactionResult : String(meta),
      ledgerIndex: response.result.ledger_index ?? null,
    };
  }

  explorerLink(hash) {
    return this.network.explorer + hash;
  }
}

function isAccountNotFound(error) {
  const code = error?.data?.error || error?.message || '';
  return String(code).includes('actNotFound');
}

export function dropsToXrp(drops) {
  return (Number(drops) / 1_000_000).toFixed(6);
}

export function availableNetworks() {
  return Object.values(NETWORKS);
}
