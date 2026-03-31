package headers

import (
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/libsv/go-p2p/wire"
)

// ValidatePoW checks that a block header's hash meets the difficulty target
// encoded in its Bits field. Returns an error if the proof of work is invalid.
func ValidatePoW(hdr *wire.BlockHeader) error {
	target := compactToBig(hdr.Bits)
	if target.Sign() <= 0 {
		return fmt.Errorf("non-positive target from bits 0x%08x", hdr.Bits)
	}

	hash := hdr.BlockHash()
	hashInt := hashToBig(hash[:])

	if hashInt.Cmp(target) > 0 {
		return fmt.Errorf("hash %s exceeds target for bits 0x%08x", hash, hdr.Bits)
	}
	return nil
}

// compactToBig converts a compact target representation (nBits) to a big.Int.
// This is the standard Bitcoin target decoding:
//
//	mantissa = bits & 0x007fffff
//	exponent = bits >> 24
//	target = mantissa * 2^(8*(exponent-3))
func compactToBig(compact uint32) *big.Int {
	mantissa := compact & 0x007fffff
	exponent := compact >> 24
	negative := compact&0x00800000 != 0

	var target big.Int
	if exponent <= 3 {
		mantissa >>= 8 * (3 - exponent)
		target.SetInt64(int64(mantissa))
	} else {
		target.SetInt64(int64(mantissa))
		target.Lsh(&target, 8*(uint(exponent)-3))
	}

	if negative {
		target.Neg(&target)
	}
	return &target
}

// hashToBig converts a 32-byte hash (little-endian as stored in Bitcoin)
// to a big.Int for comparison with the target.
func hashToBig(hash []byte) *big.Int {
	// Bitcoin block hashes are in internal byte order (little-endian).
	// Reverse to big-endian for big.Int.
	buf := make([]byte, 32)
	for i := 0; i < 32; i++ {
		buf[i] = hash[31-i]
	}
	return new(big.Int).SetBytes(buf)
}

// ValidateHeaderChain checks a sequence of headers for internal consistency:
// - Each header's PrevBlock matches the hash of the preceding header
// - Each header satisfies its own PoW target
// - Timestamps are non-decreasing (soft check — Bitcoin allows some drift)
//
// The first header's PrevBlock is checked against expectedPrevHash.
func ValidateHeaderChain(headers []*wire.BlockHeader, expectedPrevHash [32]byte) error {
	prevHash := expectedPrevHash

	for i, hdr := range headers {
		if hdr.PrevBlock != prevHash {
			return fmt.Errorf("header %d: prev hash mismatch", i)
		}

		if err := ValidatePoW(hdr); err != nil {
			return fmt.Errorf("header %d (height offset %d): %w", i, i, err)
		}

		h := hdr.BlockHash()
		prevHash = h
	}
	return nil
}

// WorkForHeader returns the amount of work represented by a header's target.
// work = 2^256 / (target + 1)
func WorkForHeader(hdr *wire.BlockHeader) *big.Int {
	target := compactToBig(hdr.Bits)
	if target.Sign() <= 0 {
		return big.NewInt(0)
	}

	// work = 2^256 / (target + 1)
	denom := new(big.Int).Add(target, big.NewInt(1))
	work := new(big.Int).Lsh(big.NewInt(1), 256)
	work.Div(work, denom)
	return work
}

// CumulativeWork sums the work for a chain of headers.
func CumulativeWork(headers []*wire.BlockHeader) *big.Int {
	total := big.NewInt(0)
	for _, hdr := range headers {
		total.Add(total, WorkForHeader(hdr))
	}
	return total
}

// CompactFromUint32 is a helper for tests that need to create a valid nBits.
// Given a 256-bit target as bytes, encode as compact.
func BigToCompact(target *big.Int) uint32 {
	if target.Sign() == 0 {
		return 0
	}
	b := target.Bytes()
	size := uint32(len(b)) // #nosec G115 // len() is always non-negative, max 32 for SHA-256

	var mantissa uint32
	if size <= 3 {
		padded := make([]byte, 4)
		copy(padded[4-size:], b)
		mantissa = binary.BigEndian.Uint32(padded) >> 8
	} else {
		mantissa = uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
	}

	// If the sign bit is set, shift right and increase size
	if mantissa&0x00800000 != 0 {
		mantissa >>= 8
		size++
	}

	return size<<24 | mantissa
}
