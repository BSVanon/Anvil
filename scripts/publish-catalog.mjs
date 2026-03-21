#!/usr/bin/env node
/**
 * Republish the Anvil Explorer catalog entry.
 * Run via cron every 12 hours to keep the entry alive in the mesh.
 *
 * Usage:
 *   ANVIL_WIF=<wif> ANVIL_TOKEN=<token> node publish-catalog.mjs
 *
 * Or with defaults from env files:
 *   node publish-catalog.mjs
 */

import { PrivateKey } from '@bsv/sdk'

const WIF = process.env.ANVIL_WIF
const TOKEN = process.env.ANVIL_TOKEN
const NODE_URL = process.env.ANVIL_NODE_URL || 'http://127.0.0.1:9333'
const ORIGIN = process.env.ANVIL_EXPLORER_ORIGIN || 'eeb0d78235b83539d21a56d61df2aff1634f88e08559481fa8239d74c67cf2bd_0'

if (!WIF || !TOKEN) {
  console.error('ANVIL_WIF and ANVIL_TOKEN required')
  process.exit(1)
}

const pk = PrivateKey.fromWif(WIF)
const pubkey = Buffer.from(pk.toPublicKey().toDER()).toString('hex')

const payload = JSON.stringify({
  name: 'Anvil Explorer',
  description: 'Real-time dashboard for the Anvil mesh network',
  content_origin: ORIGIN,
  topics: ['anvil:mainnet'],
  pricing: 'free',
})

const ts = Math.floor(Date.now() / 1000)
const ttl = 86400
const canonical = `data\nanvil:catalog\n${payload}\n${ttl}\nfalse\n${ts}`
const sig = pk.sign(Array.from(Buffer.from(canonical, 'utf8')))
const sigHex = Buffer.from(sig.toDER()).toString('hex')

const env = { type: 'data', topic: 'anvil:catalog', payload, signature: sigHex, pubkey, ttl, timestamp: ts }

const res = await fetch(`${NODE_URL}/data`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${TOKEN}` },
  body: JSON.stringify(env),
})

const text = await res.text()
console.log(`${new Date().toISOString()} catalog publish: ${res.status} ${text}`)
