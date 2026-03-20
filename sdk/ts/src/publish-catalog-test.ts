/**
 * Publish test app listings to the anvil:catalog topic.
 * Run from VPS: cd /opt/sendbsv-rates && node path/to/this/file
 */
import { AnvilClient } from './index.js';

const WIF = process.env.RELAY_ORACLE_WIF;
const NODE_URL = process.env.RELAY_BRIDGE_URL || 'http://127.0.0.1:9333';

if (!WIF) { console.error('Set RELAY_ORACLE_WIF'); process.exit(1); }

const anvil = new AnvilClient({ wif: WIF, nodeUrl: NODE_URL });

async function main() {
  // Register SendBSV Rates
  let res = await anvil.publishToCatalog({
    name: 'SendBSV Rates',
    description: 'Live BSV/USD price oracle from 7 exchanges. Updated every 5 seconds.',
    version: '1.0.0',
    topics: ['oracle:rates:bsv'],
    pricing: 'free',
    contact: 'https://x.com/SendBSV',
  });
  console.log('SendBSV Rates:', res.accepted ? 'OK' : res.error);

  // Register the Explorer itself
  res = await anvil.publishToCatalog({
    name: 'Anvil Explorer',
    description: 'Real-time dashboard for the Anvil mesh. 3D topology, live data feeds, economy view.',
    version: '0.2.0',
    url: 'http://212.56.43.191:9333',
    pricing: 'free',
    contact: 'https://x.com/SendBSV',
  });
  console.log('Anvil Explorer:', res.accepted ? 'OK' : res.error);

  console.log('Done — check anvil:catalog topic');
}

main().catch(console.error);
