package routeguard

// The routes' caps and weights, from go-sdk v1.7.7 measured on amd64 as the
// peak heap in use while one request ran through its route's handler, body
// included (guard_weights_test.go asserts them).
const (
	// MaxBEEFBody caps a /submit or /overlay/submit body. It was 64 MiB, but a
	// 64 MiB submit held 595 to 697 MiB of heap, more than MemoryBudget, so
	// one such submit could never be served within the budget.
	MaxBEEFBody int64 = 16 << 20

	// BEEFExpansion is the heap one BEEF body byte may cost, over the 11.07
	// measured at 64 MiB and the 10.32 at 16 MiB: the body, its parse, the
	// engine's serializations of the transaction and its storage.
	BEEFExpansion int64 = 12

	// MaxJSONBody caps the body of /lookup, /overlay/query,
	// /requestSyncResponse, /requestForeignGASPNode and /arc-ingest. The
	// largest honest bodies are lookup questions of a few hundred bytes and
	// merkle paths of a few kilobytes.
	MaxJSONBody int64 = 1 << 20
)

// What the parse of a BEEF can hold beyond BEEFExpansion. go-sdk's
// NewBeefFromBytes, which beefnorm.Parse runs as ParseBeef ran it, keeps
// hundreds of bytes for each ten-byte element of a BEEF dense with empty
// transactions, one-leaf BUMPs and the like: at most 44.3 times the body at
// 116 bytes, 17.9 at 1 MiB and 6.5 at 8 MiB, and never more than 3.04 times
// the body plus 29.6 MB, for every shape beefscan.Default accepts (beefscan's
// calibration, made with ParseBeef). beefnorm's canonical proofs come on top
// of it: duplicate marks over 255 levels, the costliest shape, held 27.8 MB
// for a 0.7 MB body, the canonical copy included, where the body reserves
// over 42 MB (beefscan.Default's Leaves).
const (
	parseFactor    int64 = 50
	parseFloor     int64 = 64 << 10
	parseAllowance int64 = 32 << 20
)

// parseHeadroom is what ParseBeef may hold for a BEEF of n bytes beyond
// BEEFExpansion.
func parseHeadroom(n int64) int64 {
	return min(parseFactor*n+parseFloor, parseAllowance)
}

// Expansions and allowances of the JSON routes, measured with 1 MiB bodies.
const (
	// LookupExpansion: the SHIP and SLAP lookup services decode a question's
	// query into interface{} values, 39.1 times the body at most.
	LookupExpansion int64 = 48
	// LookupAllowance covers building and encoding the answer.
	LookupAllowance int64 = 8 << 20

	// GASPExpansion: the GASP routes decode their bodies into fixed structs,
	// 1.1 times the body.
	GASPExpansion int64 = 4
	// GASPAllowance covers the reply: a page of UTXOs, or one stored
	// transaction in hex.
	GASPAllowance int64 = 8 << 20

	// ArcIngestExpansion: a merkle path in hex, decoded and parsed, 5.5
	// times the body for one of 14,000 leaves.
	ArcIngestExpansion int64 = 8
	// ArcIngestAllowance covers updating the proofs of the transaction's
	// outputs.
	ArcIngestAllowance int64 = 1 << 20
)

// The guarded routes.
var (
	BEEFRoute      = Route{MaxBody: MaxBEEFBody, Expansion: BEEFExpansion, BEEF: true, ReadTimeout: BEEFReadTimeout}
	LookupRoute    = Route{MaxBody: MaxJSONBody, Expansion: LookupExpansion, Allowance: LookupAllowance, ReadTimeout: JSONReadTimeout}
	GASPRoute      = Route{MaxBody: MaxJSONBody, Expansion: GASPExpansion, Allowance: GASPAllowance, ReadTimeout: JSONReadTimeout}
	ArcIngestRoute = Route{MaxBody: MaxJSONBody, Expansion: ArcIngestExpansion, Allowance: ArcIngestAllowance, ReadTimeout: JSONReadTimeout}
)

// WithMaxBody returns r with its body capped at max instead, when max is
// positive and below r's cap: a handler's own, lower cap.
func (r Route) WithMaxBody(max int64) Route {
	if max > 0 && max < r.MaxBody {
		r.MaxBody = max
	}
	return r
}
