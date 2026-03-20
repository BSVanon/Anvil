/**
 * Standalone catalog publisher — no SDK import needed.
 * Uses same signing logic as the rates publisher.
 * Upload to VPS and run: node publish-catalog-standalone.js
 */
import { PrivateKey } from '@bsv/sdk';
import { createHmac } from 'crypto';

const WIF = process.env.RELAY_ORACLE_WIF;
const NODE_URL = process.env.RELAY_BRIDGE_URL || 'http://127.0.0.1:9333';
const AUTH_TOKEN = process.env.RELAY_AUTH_TOKEN || createHmac('sha256', WIF || '').update('anvil-api-auth').digest('hex');

if (!WIF) { console.error('Set RELAY_ORACLE_WIF'); process.exit(1); }

const pk = PrivateKey.fromWif(WIF);
const pubkey = pk.toPublicKey().toString();

function signEnvelope(type, topic, payload, ttl, durable, timestamp) {
  const preimage = [type, topic, payload, String(ttl), durable ? 'true' : 'false', String(timestamp)].join('\n');
  return pk.sign(Array.from(Buffer.from(preimage, 'utf8'))).toDER('hex');
}

async function publishCatalog(listing) {
  const payload = JSON.stringify(listing);
  const timestamp = Math.floor(Date.now() / 1000);
  const signature = signEnvelope('data', 'anvil:catalog', payload, 0, true, timestamp);

  const res = await fetch(`${NODE_URL}/data`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${AUTH_TOKEN}` },
    body: JSON.stringify({ type: 'data', topic: 'anvil:catalog', payload, pubkey, timestamp, ttl: 0, durable: true, signature }),
    signal: AbortSignal.timeout(5000),
  });
  return res.json();
}

// Register apps
const results = await Promise.all([
  publishCatalog({
    name: 'SendBSV Rates',
    description: 'Live BSV/USD price oracle from 7 exchanges. Updated every 5 seconds.',
    version: '1.0.0',
    topics: ['oracle:rates:bsv'],
    pricing: 'free',
    contact: 'https://x.com/SendBSV',
  }),
  publishCatalog({
    name: 'Anvil Explorer',
    description: 'Real-time dashboard for the Anvil mesh. 3D topology, live data feeds, economy view.',
    version: '0.2.0',
    pricing: 'free',
    contact: 'https://x.com/SendBSV',
  }),
]);

results.forEach((r, i) => console.log(`App ${i + 1}:`, r.accepted ? 'OK' : r.error));
console.log('Done — check Apps tab in Explorer');
