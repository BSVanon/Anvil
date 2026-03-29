import { AnvilClient } from 'anvil-mesh'

async function main() {
  const client = new AnvilClient({
    nodeUrl: process.env.ANVIL_NODE_URL || 'http://localhost:9333',
    wif: process.env.APP_WIF || '',
    authToken: process.env.ANVIL_TOKEN,
  })

  if (!process.env.APP_WIF) {
    throw new Error('APP_WIF is required')
  }

  await client.publish('demo:hello', {
    message: 'hello from anvil-mesh',
    ts: Date.now(),
  })

  const result = await client.query('demo:hello')
  console.log(JSON.stringify(result, null, 2))
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
