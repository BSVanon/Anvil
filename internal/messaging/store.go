package messaging

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/BSVanon/Anvil/internal/store"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

const (
	MaxMessageBoxBytes  = 128
	MaxMessageBodyBytes = 1 << 20
	expiryChunkSize     = 1000
)

var (
	ListResponseMaxMessages  = 10000
	ListResponseMaxBodyBytes = 32 << 20

	ErrInvalidRecipient    = errors.New("invalid recipient public key")
	ErrInvalidOriginNode   = errors.New("invalid origin node public key")
	ErrInvalidSender       = errors.New("invalid sender public key")
	ErrInvalidMessageID    = errors.New("invalid message ID")
	ErrInvalidMessageBox   = errors.New("messageBox required")
	ErrMessageBoxTooLarge  = errors.New("messageBox exceeds 128 bytes")
	ErrMessageBodyTooLarge = errors.New("message body exceeds 1 MiB")
	ErrInvalidMessageBody  = errors.New("message body required")
	ErrPairQuota           = errors.New("sender-recipient quota exceeded")
	ErrInboxQuota          = errors.New("recipient inbox quota exceeded")
	ErrStoreFull           = errors.New("node message store full")
)

// Message is the gossip wire type. Storage-only fields must never be added here.
type Message struct {
	MessageID  string `json:"messageId"`
	Sender     string `json:"sender"`
	Recipient  string `json:"recipient"`
	MessageBox string `json:"messageBox"`
	Body       string `json:"body"`
	Timestamp  int64  `json:"timestamp"`
}

// StoredMessage is the list/SSE view. ReceivedAt is deliberately omitted from JSON.
type StoredMessage struct {
	Message
	AttestedBy string `json:"senderAttestedBy"`
	ReceivedAt int64  `json:"-"`
}

type diskRecord struct {
	Message
	AttestedBy string `json:"senderAttestedBy"`
	ReceivedAt int64  `json:"receivedAt"`
}

type Options struct {
	TTLSeconds       int64
	MaxPairMessages  int64
	MaxPairBytes     int64
	MaxInboxMessages int64
	MaxInboxBytes    int64
	MaxStoreMessages int64
	MaxStoreBytes    int64
}

type Store struct {
	db   *leveldb.DB
	opts Options

	writeMu sync.Mutex
	seq     uint64
	now     func() time.Time

	notifier   *notificationDispatcher
	closed     bool
	closeDone  chan struct{}
	closeError error

	onListIterate func()
}

func NewStore(path string, opts Options) (*Store, error) {
	db, err := store.OpenWithRecover(path, nil)
	if err != nil {
		return nil, fmt.Errorf("open message store: %w", err)
	}
	s := &Store{db: db, opts: normalizeOptions(opts), now: time.Now}
	if s.seq, err = readUint64(db, keyMetaSeq); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("read message sequence: %w", err)
	}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	s.startNotificationDispatcher()
	return s, nil
}

func (s *Store) Send(msg *Message, originNode string) (string, error) {
	if err := validateMessage(msg, false); err != nil {
		return "", err
	}
	originNode = strings.ToLower(originNode)
	if originNode != "" {
		if _, err := parseCompressedKey(originNode); err != nil {
			return "", ErrInvalidOriginNode
		}
	}
	msg.Sender = strings.ToLower(msg.Sender)
	msg.Recipient = strings.ToLower(msg.Recipient)
	if msg.Timestamp == 0 {
		msg.Timestamp = s.now().Unix()
	}
	id, err := NewMessageID(msg, originNode)
	if err != nil {
		return "", err
	}
	msg.MessageID = id
	record := &StoredMessage{Message: *msg, AttestedBy: "local", ReceivedAt: s.now().Unix()}
	inserted, err := s.insertAndNotify(record)
	if err != nil {
		return "", err
	}
	if !inserted {
		return "", errors.New("message ID already exists")
	}
	return id, nil
}

func (s *Store) Deliver(msg *Message, attestedBy string) (bool, error) {
	if err := ValidateForwardMessage(msg); err != nil {
		return false, err
	}
	stored := *msg
	stored.Sender = strings.ToLower(stored.Sender)
	stored.Recipient = strings.ToLower(stored.Recipient)
	record := &StoredMessage{
		Message: stored, AttestedBy: strings.ToLower(attestedBy), ReceivedAt: s.now().Unix(),
	}
	return s.insertAndNotify(record)
}

func (s *Store) List(recipient, messageBox string) ([]*StoredMessage, error) {
	return s.ListN(recipient, messageBox, 0)
}

func (s *Store) ListN(recipient, messageBox string, limit int) ([]*StoredMessage, error) {
	recipient, err := normalizeRecipient(recipient)
	if err != nil {
		return nil, err
	}
	if err := validateMessageBox(messageBox); err != nil {
		return nil, err
	}
	results := make([]*StoredMessage, 0)
	bodyBytes := 0
	iter := s.db.NewIterator(util.BytesPrefix(primaryPrefix(recipient, messageBox)), nil)
	defer iter.Release()
	for iter.Next() {
		if s.onListIterate != nil {
			s.onListIterate()
		}
		record, err := decodeRecord(iter.Value())
		if err != nil || record.Recipient != recipient || record.MessageBox != messageBox {
			continue
		}
		// The body budget bounds every page; the message cap applies when no limit is given.
		if len(results) > 0 && ((limit == 0 && len(results) >= ListResponseMaxMessages) ||
			bodyBytes+len(record.Body) > ListResponseMaxBodyBytes) {
			break
		}
		results = append(results, record)
		bodyBytes += len(record.Body)
		if limit > 0 && len(results) >= limit {
			break
		}
	}
	if err := iter.Error(); err != nil {
		return nil, fmt.Errorf("iterate messages: %w", err)
	}
	return results, nil
}

func (s *Store) Acknowledge(recipient string, ids []string) (int, error) {
	recipient, err := normalizeRecipient(recipient)
	if err != nil {
		return 0, err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	deleted := 0
	for _, id := range ids {
		primary, err := s.db.Get(indexKey(recipient, id), nil)
		if errors.Is(err, leveldb.ErrNotFound) {
			continue
		}
		if err != nil {
			return deleted, fmt.Errorf("read message index: %w", err)
		}
		if ok, err := s.deletePrimaryLocked(primary); err != nil {
			return deleted, err
		} else if ok {
			deleted++
		}
	}
	return deleted, nil
}

func (s *Store) ExpireOld() int {
	cutoff := s.now().Unix() - s.opts.TTLSeconds
	expired := 0
	deletionErrors := 0
	defer func() {
		if deletionErrors > 0 {
			log.Printf("messagebox store expiry: %d deletion errors", deletionErrors)
		}
	}()
	for {
		expiryKeys, primaries := s.expiredKeys(cutoff, expiryChunkSize)
		if len(expiryKeys) == 0 {
			return expired
		}
		processed := 0
		s.writeMu.Lock()
		for i, primary := range primaries {
			ok, err := s.deletePrimaryLocked(primary)
			if err != nil {
				deletionErrors++
				continue
			}
			if ok {
				expired++
				processed++
				continue
			}
			batch := new(leveldb.Batch)
			batch.Delete(expiryKeys[i])
			if err := s.db.Write(batch, nil); err == nil {
				processed++
			} else {
				deletionErrors++
			}
		}
		s.writeMu.Unlock()
		if processed == 0 {
			return expired
		}
	}
}

func (s *Store) Count() int {
	c, err := readCounter(s.db, keyNodeCounter)
	if err != nil {
		return 0
	}
	return int(c.Count)
}

func validateMessage(msg *Message, migration bool) error {
	if msg == nil {
		return errors.New("message required")
	}
	if !migration {
		if _, err := normalizeRecipient(msg.Recipient); err != nil {
			return err
		}
		if err := validateMessageBox(msg.MessageBox); err != nil {
			return err
		}
	}
	if msg.Body == "" {
		return ErrInvalidMessageBody
	}
	if len(msg.Body) > MaxMessageBodyBytes {
		return ErrMessageBodyTooLarge
	}
	return nil
}

func validateMessageBox(box string) error {
	if box == "" {
		return ErrInvalidMessageBox
	}
	if len(box) > MaxMessageBoxBytes {
		return ErrMessageBoxTooLarge
	}
	for i := range box {
		if box[i] < 0x20 || box[i] == 0x7f {
			return ErrInvalidMessageBox
		}
	}
	return nil
}

func validateDeliveryEnvelope(msg *Message) error {
	if msg == nil {
		return errors.New("message required")
	}
	if _, err := parseCompressedKey(msg.Sender); err != nil {
		return ErrInvalidSender
	}
	if msg.MessageID == "" || len(msg.MessageID) > MaxMessageIDBytes {
		return ErrInvalidMessageID
	}
	for i := 0; i < len(msg.MessageID); i++ {
		if msg.MessageID[i] < 0x21 || msg.MessageID[i] > 0x7e {
			return ErrInvalidMessageID
		}
	}
	return nil
}

// ValidateForwardMessage validates an incoming gossip message without storing it.
func ValidateForwardMessage(msg *Message) error {
	if err := validateDeliveryEnvelope(msg); err != nil {
		return err
	}
	return validateMessage(msg, false)
}

func normalizeRecipient(recipient string) (string, error) {
	recipient = strings.ToLower(recipient)
	if _, err := parseCompressedKey(recipient); err != nil {
		return "", ErrInvalidRecipient
	}
	return recipient, nil
}

func parseCompressedKey(value string) (*ec.PublicKey, error) {
	if len(value) != 66 {
		return nil, ErrInvalidRecipient
	}
	b, err := decodeHex(value)
	if err != nil || len(b) != 33 || (b[0] != 2 && b[0] != 3) {
		return nil, ErrInvalidRecipient
	}
	return ec.PublicKeyFromBytes(b)
}

func encodeRecord(record *StoredMessage) ([]byte, error) {
	return json.Marshal(diskRecord{Message: record.Message, AttestedBy: record.AttestedBy, ReceivedAt: record.ReceivedAt})
}

func decodeRecord(data []byte) (*StoredMessage, error) {
	var record diskRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}
	return &StoredMessage{Message: record.Message, AttestedBy: record.AttestedBy, ReceivedAt: record.ReceivedAt}, nil
}
