# Operator Guide — Gateway Mode

This covers how `[gateway]` routes a request between this node's own API and a publisher's
own domain, how `api_host` is resolved and validated, and the fixed rate limits gateway mode
applies. It does not cover the sites file's format or the CLI that manages it — see the
`anvil gateway sites --help` command for those operations.

## Routing order

Every request to a gateway-enabled listener is dispatched by its Host header, normalised
first (lower-cased, any `:port` stripped, one trailing dot stripped — so `Admin.Example.ORG`,
`admin.example.org:9333` and `admin.example.org.` all compare equal):

1. **The Host equals `api_host`, or is a loopback name** — `localhost`, an IPv4 literal
   anywhere in `127.0.0.0/8`, or `::1` (bracketed or not, with or without a port) — the
   request reaches this node's own API.
2. **Otherwise, if the Host is an allowed site** (an entry in the sites file, or an origin the
   Host's `_ordfs` TXT record names), the request reaches that site's content.
3. **Anything else** gets a plain 404.

The loopback rule exists so the local CLI and `anvil doctor` keep working on a gateway node —
they reach the API at `http://127.0.0.1:9333` and `http://localhost:9333` regardless of what
`api_host` is configured to. It adds no exposure: the API is already fully public at
`api_host`, so a loopback caller reaching the same API changes nothing about what's exposed,
only where from.

**An empty `api_host` is never a wildcard.** With no `api_host` configured, only a loopback
Host reaches the API — every other Host falls through to step 2 (and 404s there unless it
happens to be an allowed site). This is a fail-closed design: a gateway node should never end
up silently exposing its full API under an arbitrary Host header just because `api_host` was
left unset. In practice this case shouldn't arise — `api_host` is required whenever
`[gateway] enabled` is true (see below) — but the Router itself enforces the fail-closed rule
unconditionally, not just when configuration happens to be correct.

## `api_host`: default and failure rules

`api_host` is resolved once, when the config is loaded:

- **If unset,** it defaults to the host of `[node] public_url`. Overlay federation calls this
  node at `public_url`, so leaving `api_host` unset on a node that already sets `public_url`
  (the common case for a node turning gateway mode on) gets a working, consistent value for
  free.
- **If `[gateway] enabled` is true and api_host still can't be resolved** — both `api_host`
  and `public_url` are empty — config loading fails outright, with a clear message. A gateway
  node with no reachable `api_host` would mean the routing order above never reaches its own
  API via any configured name, which is never the intended state.
- **If both `api_host` and `public_url` are explicitly set and their hosts disagree,**
  config loading also fails. Overlay federation calls this node at `public_url`; if Router is
  actually keyed off a different `api_host`, federation traffic arriving at `public_url`'s
  host would 404 instead of reaching the API.
- **`api_host` must not also be listed in the sites file.** If the sites file has a `domain`
  entry equal to `api_host`, config loading fails outright — the API always wins over a site
  at the same name (Router checks `api_host` first, unconditionally), so listing it as a site
  too is a misconfiguration, not a harmless no-op. If a sites-file edit introduces this
  overlap on a running node (picked up by the hot-reload ticker rather than at config load),
  the conflicting entry is instead dropped from that reload's snapshot, with one warning
  logged — the node keeps running on its last-good routing rather than failing a restart it
  never had to do.

## Certificate registrations

`[gateway] allow_registration = true` mounts the certificate-gated
`POST /gateway/sites` and `DELETE /gateway/sites/{domain}` routes. It requires
`[gateway] enabled = true` and a valid `[certgate]` section. The daemon writes
these entries to `<data_dir>/gateway-registrations.conf`, using the same lock
and atomic replacement as the operator sites file. It never writes the
operator file. The live allowlist merges both files; a missing registrations
file is empty, and a parse error keeps the last good merged snapshot.

Operator-file domains cannot be changed through the API. Registrations are
owned by the authenticated identity, capped at 10 per identity and 1,000 in
total, and removed for that identity on certificate revocation. Registration
does not choose content: the domain's `_ordfs` TXT record remains authoritative.

This switch shares one BRC-31 handshake with the messagebox routes. Enabling it,
or `[messaging] require_sender_certificate`, requests a certificate from every
BRC-31 client. A client without one cannot authenticate to message reads or any
other BRC-31 route on the host.

## Versioned content

Gateway content uses the same ORDFS-compatible version tracker as the node API.
A site may request `/content/<origin>?seq=N` or the `:N` path form. Sequence 0
is the tracked origin and every spend advances the sequence, including a plain
transfer without a new inscription. Responses carry `X-Ord-Seq`. An explicit
sequence becomes `immutable` only after the resolved location has at least six
confirmations; this confirmation rule is Anvil's documented divergence from
ORDFS. See [Proof and Content Endpoints](../API_REFERENCE.md#proof-and-content-endpoints)
for the complete cache and numbering contract.
When enforcing its content-scope limits, the gateway scans the origin and latest-version trees before older-version roots.

## TLS and ACME

Gateway mode starts HTTPS on `[gateway] https_listen` (default `:443`) and an
HTTP listener on `http_listen` (default `:80`). Port 80 serves ACME HTTP-01 and
redirects other allowed hosts to HTTPS. Certificates and the ACME account are
cached in `<data_dir>/acme`; only the API host and currently allowed site hosts
are eligible for certificates. The default ACME directory is the production
Let's Encrypt directory, and `acme_accept_tos` defaults to `false`, so an
operator must explicitly accept the CA terms before issuance can succeed.

Optional `acme_email` supplies the ACME account contact. Allowed mesh peers can
replicate short-lived challenge entries so more than one gateway can answer a
validation. A listener bind failure is logged without stopping the node's mesh
or API listener, so use `anvil doctor` to catch an unavailable gateway port.

`anvil doctor` checks the gateway mode and sites file, each domain's `_ordfs`
TXT answer, ports 80 and 443, the terms switch, cached certificate state and
cache-directory ownership/mode, the closed-network settings, and whether an
allowed peer is connected for challenge replication.
When its local API is unavailable, it reports that failure once and skips only the checks that require the API.

## Fixed rates

Two rate limits are part of gateway mode's own traffic shaping, both fixed, built-in constants
for this release — not `[gateway]` config keys:

| Limit | Rate | Burst | Applies to |
|---|---|---|---|
| TXT flood guard | 5/s | 20 | `_ordfs` TXT lookups for a Host with no `domain` entry in the sites file (it can only possibly match through an `origin` entry) — bounds how fast an arbitrary Host header can drive new DNS lookups. Only ever consulted on a genuine resolver cache miss; a cached answer is never throttled, however busy this guard's global bucket is. |
| Site traffic limiter | 50 req/s | 200 | Per-client requests to a site's own content (`/` and `/content/...`), independent of the TXT flood guard above. Respects `trust_proxy` the same way the node's own API rate limiter does. |

Making these configurable is tracked for a later release, not this one.
