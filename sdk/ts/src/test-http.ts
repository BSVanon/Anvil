/**
 * HTTP-layer integration tests for the anvil-mesh SDK.
 *
 * Spins up a mock HTTP server that records requests and returns canned
 * responses, then exercises each client method against it. Covers the v0.3
 * methods (discovery, messaging, metadata) and the Path C methods (peers,
 * health) that previously had no direct test coverage.
 *
 * Does not cover subscribeMessages() — that uses EventSource which requires
 * a DOM-compatible runtime. Construction-only smoke test for that method is
 * in test.ts.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { createServer, IncomingMessage, ServerResponse, Server } from 'node:http';
import { AddressInfo } from 'node:net';
import { AnvilClient } from './index.js';

const TEST_WIF = 'L5XAvuHrAVMkgNJtCaLNitZTkG7L9NtX7AKtrH8CZY1jeJtzAijQ';

interface CapturedRequest {
  method: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

function startMockServer(
  handler: (req: CapturedRequest, res: ServerResponse) => void
): Promise<{ server: Server; url: string }> {
  return new Promise((resolve) => {
    const server = createServer((req: IncomingMessage, res: ServerResponse) => {
      let body = '';
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', () => {
        handler({
          method: req.method || 'GET',
          path: req.url || '/',
          headers: req.headers as Record<string, string | string[] | undefined>,
          body,
        }, res);
      });
    });
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as AddressInfo;
      resolve({ server, url: `http://127.0.0.1:${addr.port}` });
    });
  });
}

describe('SDK HTTP methods — v0.3 discovery', () => {
  let server: Server;
  let url: string;
  let lastReq: CapturedRequest | null = null;

  before(async () => {
    const mock = await startMockServer((req, res) => {
      lastReq = req;
      res.setHeader('Content-Type', 'application/json');
      if (req.path === '/topics') {
        res.end(JSON.stringify({ topics: [{ topic: 'oracle:rates', count: 42 }], count: 1 }));
      } else if (req.path.startsWith('/topics/')) {
        res.end(JSON.stringify({
          topic: { topic: decodeURIComponent(req.path.slice(8)), count: 1 },
          publisher_identity: { name: 'test-pub' },
        }));
      } else if (req.path.startsWith('/identity/')) {
        const pubkey = req.path.slice(10);
        res.end(JSON.stringify({ pubkey, identity: { name: 'alice' } }));
      } else {
        res.statusCode = 404;
        res.end('{}');
      }
    });
    server = mock.server;
    url = mock.url;
  });

  after(() => new Promise<void>((resolve) => server.close(() => resolve())));

  it('getTopics() returns topic list', async () => {
    const client = new AnvilClient({ wif: TEST_WIF, nodeUrl: url });
    const result = await client.getTopics();
    assert.ok(result, 'expected non-null result');
    assert.strictEqual(result!.count, 1);
    assert.strictEqual(result!.topics[0].topic, 'oracle:rates');
    assert.strictEqual(lastReq!.method, 'GET');
    assert.strictEqual(lastReq!.path, '/topics');
  });

  it('getTopicDetail() fetches a single topic', async () => {
    const client = new AnvilClient({ wif: TEST_WIF, nodeUrl: url });
    const result = await client.getTopicDetail('oracle:rates');
    assert.ok(result);
    assert.strictEqual(result!.topic.topic, 'oracle:rates');
    assert.ok(lastReq!.path.startsWith('/topics/'));
  });

  it('getIdentity() fetches identity by pubkey', async () => {
    const client = new AnvilClient({ wif: TEST_WIF, nodeUrl: url });
    const pubkey = '02abcdef';
    const result = await client.getIdentity(pubkey);
    assert.ok(result);
    assert.strictEqual(result!.pubkey, pubkey);
    assert.ok(lastReq!.path.startsWith('/identity/'));
  });

  it('getTopics() returns null gracefully when server errors', async () => {
    // Use a dead URL (port 1 — will refuse connection) so the HTTP call
    // throws and the try/catch wrapper returns null.
    const client = new AnvilClient({ wif: TEST_WIF, nodeUrl: 'http://127.0.0.1:1' });
    const result = await client.getTopics();
    assert.strictEqual(result, null, 'expected null on transport error');
  });
});

describe('SDK HTTP methods — messaging (BRC-33)', () => {
  let server: Server;
  let url: string;
  let lastReq: CapturedRequest | null = null;

  before(async () => {
    const mock = await startMockServer((req, res) => {
      lastReq = req;
      res.setHeader('Content-Type', 'application/json');
      if (req.path === '/sendMessage') {
        res.end(JSON.stringify({ status: 'ok', messageId: 'msg-123' }));
      } else if (req.path === '/listMessages') {
        res.end(JSON.stringify({ status: 'ok', messages: [{ messageId: 'msg-1', body: 'hi' }] }));
      } else if (req.path === '/acknowledgeMessage') {
        res.end(JSON.stringify({ status: 'ok', acknowledged: 1 }));
      } else {
        res.statusCode = 404;
        res.end('{}');
      }
    });
    server = mock.server;
    url = mock.url;
  });

  after(() => new Promise<void>((resolve) => server.close(() => resolve())));

  it('sendMessage() posts to /sendMessage with auth header', async () => {
    const client = new AnvilClient({ wif: TEST_WIF, nodeUrl: url });
    const result = await client.sendMessage('02deadbeef', 'inbox', 'hello');
    assert.strictEqual(result.messageId, 'msg-123');
    assert.strictEqual(lastReq!.method, 'POST');
    assert.strictEqual(lastReq!.path, '/sendMessage');
    // SDK uses Authorization: Bearer <token>; verify the token is present
    const authHeader = String(lastReq!.headers['authorization'] || '');
    assert.match(authHeader, /^Bearer [0-9a-f]{64}$/, `unexpected auth header: ${authHeader}`);
    const body = JSON.parse(lastReq!.body);
    assert.strictEqual(body.recipient, '02deadbeef');
    assert.strictEqual(body.messageBox, 'inbox');
    assert.strictEqual(body.body, 'hello');
  });

  it('listMessages() returns array of messages', async () => {
    const client = new AnvilClient({ wif: TEST_WIF, nodeUrl: url });
    const result = await client.listMessages('inbox');
    assert.strictEqual(result.messages.length, 1);
    assert.strictEqual(result.messages[0].messageId, 'msg-1');
  });

  it('acknowledgeMessages() sends message IDs for deletion', async () => {
    const client = new AnvilClient({ wif: TEST_WIF, nodeUrl: url });
    const result = await client.acknowledgeMessages(['msg-1', 'msg-2']);
    assert.strictEqual(result.acknowledged, 1);
    const body = JSON.parse(lastReq!.body);
    assert.deepStrictEqual(body.messageIds, ['msg-1', 'msg-2']);
  });
});

describe('SDK HTTP methods — Path C (peers, health)', () => {
  let server: Server;
  let url: string;
  let lastReq: CapturedRequest | null = null;

  before(async () => {
    const mock = await startMockServer((req, res) => {
      lastReq = req;
      res.setHeader('Content-Type', 'application/json');
      if (req.path === '/mesh/nodes') {
        res.end(JSON.stringify({
          nodes: [
            { identity: 'self-id', name: 'anvil-prime', version: '0.3.0', url: 'https://anvil.sendbsv.com',
              last_seen: '2026-04-17T10:00:00Z', evidence: { self: true, direct_peer: false, heartbeat: false, overlay: false } },
          ],
          count: 1,
        }));
      } else if (req.path === '/mesh/status') {
        res.end(JSON.stringify({
          node: 'anvil-prime',
          version: '0.3.0',
          headers: { height: 944988, work: '0xabcd' },
          upstream_status: { broadcast: 'healthy', headers_sync_lag_secs: 12 },
        }));
      } else {
        res.statusCode = 404;
        res.end('{}');
      }
    });
    server = mock.server;
    url = mock.url;
  });

  after(() => new Promise<void>((resolve) => server.close(() => resolve())));

  it('peers() returns federation directory', async () => {
    const client = new AnvilClient({ wif: TEST_WIF, nodeUrl: url });
    const result = await client.peers();
    assert.strictEqual(result.count, 1);
    assert.strictEqual(result.nodes[0].name, 'anvil-prime');
    assert.strictEqual(result.nodes[0].evidence.self, true);
    assert.strictEqual(lastReq!.method, 'GET');
    assert.strictEqual(lastReq!.path, '/mesh/nodes');
  });

  it('health() returns upstream_status for failover', async () => {
    const client = new AnvilClient({ wif: TEST_WIF, nodeUrl: url });
    const result = await client.health();
    assert.ok(result.upstream_status, 'upstream_status must be present');
    assert.strictEqual(result.upstream_status!.broadcast, 'healthy');
    assert.strictEqual(result.upstream_status!.headers_sync_lag_secs, 12);
    assert.strictEqual(lastReq!.path, '/mesh/status');
  });
});

describe('SDK HTTP methods — publish / query / catalog', () => {
  let server: Server;
  let url: string;
  let lastReq: CapturedRequest | null = null;

  before(async () => {
    const mock = await startMockServer((req, res) => {
      lastReq = req;
      res.setHeader('Content-Type', 'application/json');
      if (req.path === '/data' && req.method === 'POST') {
        res.end(JSON.stringify({ accepted: true }));
      } else if (req.path.startsWith('/data') && req.method === 'GET') {
        res.end(JSON.stringify({ topic: 'test', count: 0, envelopes: [] }));
      } else if (req.path === '/status') {
        res.end(JSON.stringify({ node: 'test', version: '0.3.0', headers: { height: 1, work: '0' } }));
      } else {
        res.statusCode = 404;
        res.end('{}');
      }
    });
    server = mock.server;
    url = mock.url;
  });

  after(() => new Promise<void>((resolve) => server.close(() => resolve())));

  it('publish() posts a signed envelope and parses response', async () => {
    const client = new AnvilClient({ wif: TEST_WIF, nodeUrl: url });
    const result = await client.publish('test:topic', { value: 1 });
    assert.strictEqual(result.accepted, true);
    assert.strictEqual(lastReq!.method, 'POST');
    assert.strictEqual(lastReq!.path, '/data');
    const env = JSON.parse(lastReq!.body);
    // Signed envelope carries signature + pubkey
    assert.ok(env.signature, 'envelope must be signed');
    assert.ok(env.pubkey, 'envelope must include pubkey');
    assert.strictEqual(env.topic, 'test:topic');
  });

  it('query() fetches envelopes for a topic', async () => {
    const client = new AnvilClient({ wif: TEST_WIF, nodeUrl: url });
    const result = await client.query('test:topic', 10);
    assert.strictEqual(result.topic, 'test');
    assert.ok(lastReq!.path.includes('/data'));
    assert.ok(lastReq!.path.includes('topic=test%3Atopic'));
    assert.ok(lastReq!.path.includes('limit=10'));
  });

  it('status() returns node health', async () => {
    const client = new AnvilClient({ wif: TEST_WIF, nodeUrl: url });
    const result = await client.status();
    assert.strictEqual(result.node, 'test');
    assert.strictEqual(result.headers.height, 1);
  });
});
