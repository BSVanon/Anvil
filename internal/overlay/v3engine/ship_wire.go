package v3engine

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

// parseTopicsHeader accepts the current comma-separated x-topics form and
// the earlier JSON string-array form. Both forms share the same distinct-topic
// cap and deduplication.
func parseTopicsHeader(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var topics []string
	if strings.HasPrefix(raw, "[") {
		if err := json.Unmarshal([]byte(raw), &topics); err != nil {
			return nil, err
		}
	} else {
		topics = strings.Split(raw, ",")
		for i := range topics {
			topics[i] = strings.TrimSpace(topics[i])
			if topics[i] == "" {
				return nil, errors.New("empty topic")
			}
		}
	}
	return dedupTopics(topics)
}

// splitOffChainValues separates the current TypeScript framing:
// varint(BEEF byte length), BEEF, then off-chain values. The earlier Anvil
// prefix-length order remains accepted when the current position does not
// start with a recognized BEEF prefix and the earlier position does.
func splitOffChainValues(body []byte, header string) (beef, offChain []byte, err error) {
	if header != "true" {
		return body, nil, nil
	}
	if len(body) == 0 {
		return nil, nil, errors.New("empty body")
	}
	n, advance, err := readVarInt(body)
	if err != nil {
		return nil, nil, fmt.Errorf("read varint: %w", err)
	}
	rest := body[advance:]
	if n == 0 {
		return nil, nil, errors.New("empty BEEF")
	}
	if n > uint64(len(rest)) {
		return nil, nil, fmt.Errorf("BEEF length declares %d bytes but only %d available", n, len(rest))
	}
	beef, offChain = rest[:n], rest[n:]
	legacyBeef := rest[n:]
	if !hasBEEFPrefix(beef) && hasBEEFPrefix(legacyBeef) {
		return legacyBeef, rest[:n], nil
	}
	return beef, offChain, nil
}

func hasBEEFPrefix(body []byte) bool {
	if len(body) < 4 {
		return false
	}
	version := binary.LittleEndian.Uint32(body[:4])
	return version == transaction.BEEF_V1 || version == transaction.BEEF_V2 || version == transaction.ATOMIC_BEEF
}

// readVarInt decodes a Bitcoin-flavored variable-length integer from the
// beginning of buf and returns its value and encoded width.
func readVarInt(buf []byte) (uint64, int, error) {
	if len(buf) == 0 {
		return 0, 0, errors.New("empty buffer")
	}
	switch first := buf[0]; {
	case first < 0xfd:
		return uint64(first), 1, nil
	case first == 0xfd:
		if len(buf) < 3 {
			return 0, 0, errors.New("truncated varint (0xfd)")
		}
		return uint64(binary.LittleEndian.Uint16(buf[1:3])), 3, nil
	case first == 0xfe:
		if len(buf) < 5 {
			return 0, 0, errors.New("truncated varint (0xfe)")
		}
		return uint64(binary.LittleEndian.Uint32(buf[1:5])), 5, nil
	default:
		if len(buf) < 9 {
			return 0, 0, errors.New("truncated varint (0xff)")
		}
		return binary.LittleEndian.Uint64(buf[1:9]), 9, nil
	}
}
