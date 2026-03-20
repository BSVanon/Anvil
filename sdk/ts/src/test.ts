import { describe, it } from 'node:test';
import assert from 'node:assert';
import { AnvilClient, deriveAuthToken } from './index.js';
import { PrivateKey, Signature } from '@bsv/sdk';

describe('deriveAuthToken', () => {
  it('produces deterministic hex token from WIF', () => {
    const token = deriveAuthToken('***REMOVED-KEY***');
    assert.strictEqual(typeof token, 'string');
    assert.strictEqual(token.length, 64); // 32 bytes hex
    // Same WIF should always produce the same token
    assert.strictEqual(token, deriveAuthToken('***REMOVED-KEY***'));
  });

  it('different WIFs produce different tokens', () => {
    const a = deriveAuthToken('***REMOVED-KEY***');
    const b = deriveAuthToken('***REMOVED-KEY***');
    assert.notStrictEqual(a, b);
  });
});

describe('AnvilClient constructor', () => {
  it('derives pubkey and auth token from WIF', () => {
    const client = new AnvilClient({
      wif: '***REMOVED-KEY***',
      nodeUrl: 'http://localhost:9333',
    });
    assert.strictEqual(typeof client.getPubkey(), 'string');
    assert.strictEqual(client.getPubkey().length, 66); // compressed pubkey hex
    assert.strictEqual(typeof client.getAuthToken(), 'string');
    assert.strictEqual(client.getAuthToken().length, 64);
  });
});

describe('envelope signing', () => {
  const wif = '***REMOVED-KEY***';
  const pk = PrivateKey.fromWif(wif);
  const pubkey = pk.toPublicKey();

  /**
   * Rebuild the Go-side canonical preimage and verify the SDK signature.
   * This catches any divergence between SDK signing and Anvil validation.
   */
  function verifySignature(
    sig: string, type: string, topic: string, payload: string,
    ttl: number, durable: boolean, timestamp: number,
    noGossip: boolean, monetization?: { model: string; payee_locking_script_hex?: string; price_sats?: number; auth_pubkey?: string }
  ): boolean {
    // Rebuild preimage exactly as Go's SigningDigest does
    let preimage = [type, topic, payload, String(ttl), durable ? 'true' : 'false', String(timestamp)].join('\n');
    if (noGossip) preimage += '\nno_gossip';
    if (monetization) {
      preimage += '\n' + monetization.model;
      if (monetization.payee_locking_script_hex) preimage += '\n' + monetization.payee_locking_script_hex;
      if (monetization.price_sats && monetization.price_sats > 0) preimage += '\n' + String(monetization.price_sats);
      if (monetization.auth_pubkey) preimage += '\n' + monetization.auth_pubkey;
    }

    // @bsv/sdk verify() internally SHA-256s — pass raw preimage, same as sign()
    const sigObj = Signature.fromDER(sig, 'hex');
    return pubkey.verify(Array.from(Buffer.from(preimage, 'utf8')), sigObj);
  }

  it('plain envelope signature matches Go verification', () => {
    const client = new AnvilClient({ wif, nodeUrl: 'http://localhost:9333' });
    // Access private method via any-cast for testing
    const sig = (client as any).signEnvelope('data', 'test:topic', '{"val":1}', 120, false, 1700000000, false, undefined);
    assert.strictEqual(typeof sig, 'string');
    assert.ok(sig.length > 50, 'DER signature should be >50 chars');
    assert.ok(verifySignature(sig, 'data', 'test:topic', '{"val":1}', 120, false, 1700000000, false), 'signature must verify');
  });

  it('no_gossip envelope signature includes flag in digest', () => {
    const client = new AnvilClient({ wif, nodeUrl: 'http://localhost:9333' });
    const sigWithout = (client as any).signEnvelope('data', 'test:topic', 'x', 60, false, 1700000000, false, undefined);
    const sigWith = (client as any).signEnvelope('data', 'test:topic', 'x', 60, false, 1700000000, true, undefined);
    // Different digests must produce different signatures
    assert.notStrictEqual(sigWithout, sigWith, 'no_gossip flag must change the signature');
    // Both must verify with their respective preimages
    assert.ok(verifySignature(sigWithout, 'data', 'test:topic', 'x', 60, false, 1700000000, false));
    assert.ok(verifySignature(sigWith, 'data', 'test:topic', 'x', 60, false, 1700000000, true));
  });

  it('monetized envelope signature includes monetization in digest', () => {
    const client = new AnvilClient({ wif, nodeUrl: 'http://localhost:9333' });
    const mon = { model: 'passthrough', payee_locking_script_hex: '76a914abcd1234ef88ac', price_sats: 50 };
    const sigPlain = (client as any).signEnvelope('data', 'test:paid', 'data', 60, false, 1700000000, false, undefined);
    const sigMon = (client as any).signEnvelope('data', 'test:paid', 'data', 60, false, 1700000000, false, mon);
    assert.notStrictEqual(sigPlain, sigMon, 'monetization must change the signature');
    assert.ok(verifySignature(sigPlain, 'data', 'test:paid', 'data', 60, false, 1700000000, false));
    assert.ok(verifySignature(sigMon, 'data', 'test:paid', 'data', 60, false, 1700000000, false, mon));
  });
});
