/**
 * anvil-mesh — Thin TypeScript client for the Anvil mesh network.
 *
 * Handles auth token derivation, envelope signing, publish, and query.
 * Eliminates the pain points that burned us with SendBSV-Rates:
 *   - HMAC auth token derivation (no more guessing)
 *   - @bsv/sdk sign() double-hash (pass raw preimage, not pre-hash)
 *   - Envelope preimage format (handled internally)
 */

import { PrivateKey, Hash } from '@bsv/sdk';
import { createHmac } from 'crypto';

// ── Types ──

export interface Envelope {
  type: string;
  topic: string;
  payload: string;
  pubkey: string;
  signature: string;
  timestamp: number;
  ttl: number;
  durable?: boolean;
  no_gossip?: boolean;
  monetization?: {
    model: string;
    payee_locking_script_hex?: string;
    price_sats?: number;
    auth_pubkey?: string;
  };
}

export interface DataResponse {
  topic: string;
  count: number;
  envelopes: Envelope[];
}

export interface NodeStatus {
  node: string;
  version: string;
  headers: { height: number; work: string };
}

export interface NodeStats extends NodeStatus {
  envelopes?: { ephemeral: number; durable: number; topics: Record<string, number> };
  mesh?: { peers: number };
  overlay?: { ship_count: number };
}

/** App listing for the anvil:catalog topic. */
export interface CatalogListing {
  /** App name (e.g. "SendBSV Rates") */
  name: string;
  /** Short description */
  description: string;
  /** Version string */
  version?: string;
  /** On-chain content origin (txid_vout) — used by /app/{name} and /explorer redirect */
  content_origin?: string;
  /** URL to access the app (if web-based) */
  url?: string;
  /** Data topics this app publishes to */
  topics?: string[];
  /** Payment model: "free", "paid", "freemium" */
  pricing?: string;
  /** Contact URL (e.g. X/Twitter, website) */
  contact?: string;
}

export interface PublishOptions {
  ttl?: number;
  durable?: boolean;
  noGossip?: boolean;
  monetization?: Envelope['monetization'];
}

export interface AnvilClientConfig {
  /** WIF private key for signing envelopes and deriving auth token */
  wif: string;
  /** Anvil node API URL (e.g. http://212.56.43.191:9333) */
  nodeUrl: string;
  /** Request timeout in ms (default: 10000) */
  timeout?: number;
}

// ── Client ──

export class AnvilClient {
  private pk: PrivateKey;
  private pubkeyHex: string;
  private authToken: string;
  private nodeUrl: string;
  private timeout: number;

  constructor(config: AnvilClientConfig) {
    this.pk = PrivateKey.fromWif(config.wif);
    this.pubkeyHex = this.pk.toPublicKey().toString();
    this.authToken = deriveAuthToken(config.wif);
    this.nodeUrl = config.nodeUrl.replace(/\/$/, '');
    this.timeout = config.timeout ?? 10000;
  }

  /** Publish a data envelope to the mesh. */
  async publish(topic: string, data: unknown, opts: PublishOptions = {}): Promise<{ accepted: boolean; error?: string }> {
    const payload = typeof data === 'string' ? data : JSON.stringify(data);
    const timestamp = Math.floor(Date.now() / 1000);
    const ttl = opts.ttl ?? 120;
    const durable = opts.durable ?? false;

    const signature = this.signEnvelope('data', topic, payload, ttl, durable, timestamp, opts.noGossip ?? false, opts.monetization);

    const envelope: Record<string, unknown> = {
      type: 'data',
      topic,
      payload,
      pubkey: this.pubkeyHex,
      timestamp,
      ttl,
      durable,
      signature,
    };

    if (opts.noGossip) envelope.no_gossip = true;
    if (opts.monetization) envelope.monetization = opts.monetization;

    const res = await this.post('/data', envelope);
    return res as { accepted: boolean; error?: string };
  }

  /** Query envelopes by topic. */
  async query(topic: string, limit = 25): Promise<DataResponse> {
    return this.get(`/data?topic=${encodeURIComponent(topic)}&limit=${limit}`) as Promise<DataResponse>;
  }

  /**
   * Publish an app listing to the anvil:catalog topic.
   * Other nodes in the mesh and the Explorer's Apps tab will discover it.
   */
  async publishToCatalog(listing: CatalogListing): Promise<{ accepted: boolean; error?: string }> {
    return this.publish('anvil:catalog', listing, { ttl: 0, durable: true });
  }

  /** Query the app catalog. */
  async getCatalog(limit = 50): Promise<DataResponse> {
    return this.query('anvil:catalog', limit);
  }

  /** Get node status. */
  async status(): Promise<NodeStatus> {
    return this.get('/status') as Promise<NodeStatus>;
  }

  /** Get extended node stats. */
  async stats(): Promise<NodeStats> {
    return this.get('/stats') as Promise<NodeStats>;
  }

  /** Get the derived auth token (useful for debugging). */
  getAuthToken(): string {
    return this.authToken;
  }

  /** Get the public key hex. */
  getPubkey(): string {
    return this.pubkeyHex;
  }

  // ── Internal ──

  private signEnvelope(
    type: string, topic: string, payload: string, ttl: number,
    durable: boolean, timestamp: number, noGossip: boolean, monetization?: Envelope['monetization']
  ): string {
    let preimage = [type, topic, payload, String(ttl), durable ? 'true' : 'false', String(timestamp)].join('\n');

    // no_gossip appended when true — must match Go's SigningDigest
    if (noGossip) {
      preimage += '\nno_gossip';
    }

    // Monetization appended when present — must match Go's SigningDigest exactly
    if (monetization) {
      preimage += '\n' + monetization.model;
      if (monetization.payee_locking_script_hex) {
        preimage += '\n' + monetization.payee_locking_script_hex;
      }
      if (monetization.price_sats && monetization.price_sats > 0) {
        preimage += '\n' + String(monetization.price_sats);
      }
      if (monetization.auth_pubkey) {
        preimage += '\n' + monetization.auth_pubkey;
      }
    }

    // sign() internally SHA-256s — pass raw preimage bytes, NOT a pre-hash
    const sig = this.pk.sign(Array.from(Buffer.from(preimage, 'utf8')));
    return sig.toDER('hex') as string;
  }

  private async get(path: string): Promise<unknown> {
    const res = await fetch(`${this.nodeUrl}${path}`, {
      signal: AbortSignal.timeout(this.timeout),
    });
    if (!res.ok) throw new Error(`GET ${path}: ${res.status} ${res.statusText}`);
    return res.json();
  }

  private async post(path: string, body: unknown): Promise<unknown> {
    const res = await fetch(`${this.nodeUrl}${path}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.authToken}`,
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(this.timeout),
    });
    if (!res.ok) throw new Error(`POST ${path}: ${res.status} ${res.statusText}`);
    return res.json();
  }
}

// ── Utilities ──

/** Derive the HMAC-SHA256 auth token from a WIF. Matches Anvil's server-side derivation. */
export function deriveAuthToken(wif: string): string {
  return createHmac('sha256', wif).update('anvil-api-auth').digest('hex');
}
