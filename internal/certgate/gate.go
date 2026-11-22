// Package certgate verifies certificates used for admission decisions.
package certgate

import (
	"container/list"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bsv-blockchain/go-sdk/auth/certificates"
	"github.com/bsv-blockchain/go-sdk/auth/utils"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

const (
	maxAdmissions = 10000
	lazyRetry     = time.Minute
	watchOwner    = "certgate"
)

var (
	ErrRefused          = errors.New("certificate refused")
	ErrRevoked          = errors.New("certificate revoked")
	ErrAdmissionFull    = errors.New("certificate admission cache is full")
	ErrWatchUnavailable = errors.New("certificate revocation watch is unavailable")
)

// SpendWatcher is the part of spendwatch.Watcher used by certificate admission.
type SpendWatcher interface {
	Check(context.Context, string) (bool, string, error)
	Watch(string, string) error
	Unwatch(string, string)
	OnSpent(string, func(string, string))
}

// Config configures one verifier shared by every certificate-gated use.
type Config struct {
	Certifiers       []string
	Types            []string
	RevealFields     map[string][]string
	AllowUnrevocable map[string]bool
	RevocationCheck  string
	Recheck          time.Duration
	Wallet           wallet.Interface
	Watcher          SpendWatcher
	Now              func() time.Time
	VerifySignature  func(context.Context, *certificates.Certificate) error
}

type cacheKey struct{ identity, typ, outpoint string }

type admission struct {
	outpoint string
	expires  time.Time
}

// Gate verifies certificates, caches admissions, and coordinates revocation.
type Gate struct {
	wallet     wallet.Interface
	watch      SpendWatcher
	strict     bool
	recheck    time.Duration
	now        func() time.Time
	certifiers map[string]struct{}
	types      map[string]struct{}
	fields     map[string][]string
	unrev      map[string]bool

	mu          sync.Mutex
	cache       map[cacheKey]admission
	order       *list.List
	orderByKey  map[cacheKey]*list.Element
	byOutpoint  map[string]map[cacheKey]struct{}
	pinned      map[string]string
	hooks       map[string]func(string)
	verifySpend func(context.Context, string, string) error
	verifyCert  func(context.Context, *certificates.Certificate) error

	verified   atomic.Int64
	refused    atomic.Int64
	revoked    atomic.Int64
	checkError atomic.Int64
}

// New validates cfg and constructs a Gate. No network work happens here.
func New(cfg Config) (*Gate, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	if cfg.Watcher == nil {
		return nil, errors.New("certgate: watcher is required")
	}
	if cfg.Recheck <= 0 {
		cfg.Recheck = time.Hour
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.VerifySignature == nil {
		cfg.VerifySignature = func(ctx context.Context, cert *certificates.Certificate) error {
			return cert.Verify(ctx)
		}
	}
	g := &Gate{
		wallet: cfg.Wallet, watch: cfg.Watcher, strict: cfg.RevocationCheck != "lazy",
		recheck: cfg.Recheck, now: cfg.Now, certifiers: map[string]struct{}{},
		types: map[string]struct{}{}, fields: cfg.RevealFields, unrev: cfg.AllowUnrevocable,
		cache: map[cacheKey]admission{}, order: list.New(), orderByKey: map[cacheKey]*list.Element{},
		byOutpoint: map[string]map[cacheKey]struct{}{}, pinned: map[string]string{},
		hooks:      map[string]func(string){},
		verifyCert: cfg.VerifySignature,
	}
	for _, raw := range cfg.Certifiers {
		b, err := hex.DecodeString(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("certgate: invalid certifier")
		}
		pk, err := ec.ParsePubKey(b)
		if err != nil {
			return nil, fmt.Errorf("certgate: invalid certifier")
		}
		g.certifiers[hex.EncodeToString(pk.Compressed())] = struct{}{}
	}
	for _, typ := range cfg.Types {
		if _, err := wallet.CertificateTypeFromBase64(typ); err != nil {
			return nil, fmt.Errorf("certgate: invalid certificate type")
		}
		g.types[typ] = struct{}{}
	}
	g.watch.OnSpent(watchOwner, g.onCandidateSpend)
	return g, nil
}

// ValidateConfig applies the same policy parsing used by New without
// requiring runtime dependencies such as a spend watcher.
func ValidateConfig(cfg Config) error {
	if len(cfg.Certifiers) == 0 || len(cfg.Types) == 0 {
		return errors.New("certgate: certifiers and types are required")
	}
	if cfg.RevocationCheck != "" && cfg.RevocationCheck != "strict" && cfg.RevocationCheck != "lazy" {
		return fmt.Errorf("certgate: invalid revocation check")
	}
	for _, raw := range cfg.Certifiers {
		b, err := hex.DecodeString(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("certgate: invalid certifier")
		}
		if _, err := ec.ParsePubKey(b); err != nil {
			return fmt.Errorf("certgate: invalid certifier")
		}
	}
	configuredTypes := make(map[string]struct{}, len(cfg.Types))
	for _, typ := range cfg.Types {
		if _, err := wallet.CertificateTypeFromBase64(typ); err != nil {
			return fmt.Errorf("certgate: invalid certificate type")
		}
		configuredTypes[typ] = struct{}{}
	}
	for typ := range cfg.RevealFields {
		if _, ok := configuredTypes[typ]; !ok {
			return fmt.Errorf("certgate: reveal fields contain an unconfigured certificate type")
		}
	}
	for typ := range cfg.AllowUnrevocable {
		if _, ok := configuredTypes[typ]; !ok {
			return fmt.Errorf("certgate: unrevocable policy contains an unconfigured certificate type")
		}
	}
	return nil
}

// RequestedCertificates returns the BRC-103 request represented by this gate.
func (g *Gate) RequestedCertificates() *utils.RequestedCertificateSet {
	req := &utils.RequestedCertificateSet{CertificateTypes: make(utils.RequestedCertificateTypeIDAndFieldList)}
	for raw := range g.certifiers {
		b, _ := hex.DecodeString(raw)
		pk, _ := ec.ParsePubKey(b)
		req.Certifiers = append(req.Certifiers, pk)
	}
	for typ := range g.types {
		id, _ := wallet.CertificateTypeFromBase64(typ)
		req.CertificateTypes[id] = append([]string(nil), g.fields[typ]...)
	}
	return req
}

// VerifyAny admits identity when at least one supplied certificate is valid.
func (g *Gate) VerifyAny(ctx context.Context, identity *ec.PublicKey, certs []*certificates.VerifiableCertificate) error {
	var watchErr error
	for _, cert := range certs[:min(len(certs), 8)] {
		if err := g.verify(ctx, identity, cert); err == nil {
			return nil
		} else if errors.Is(err, ErrWatchUnavailable) {
			watchErr = err
		}
	}
	g.refused.Add(1)
	if watchErr != nil {
		return watchErr
	}
	return ErrRefused
}

// Verify checks and caches one certificate for the authenticated identity.
func (g *Gate) Verify(ctx context.Context, identity *ec.PublicKey, cert *certificates.VerifiableCertificate) error {
	err := g.verify(ctx, identity, cert)
	if err != nil {
		g.refused.Add(1)
	}
	return err
}

func (g *Gate) verify(ctx context.Context, identity *ec.PublicKey, cert *certificates.VerifiableCertificate) error {
	if identity == nil || cert == nil {
		return g.reject("missing certificate or identity")
	}
	typ := string(cert.Type)
	if _, ok := g.types[typ]; !ok {
		return g.reject("certificate type is not configured")
	}
	certifier := hex.EncodeToString(cert.Certifier.Compressed())
	if _, ok := g.certifiers[certifier]; !ok {
		return g.reject("certificate certifier is not configured")
	}
	identityHex := hex.EncodeToString(identity.Compressed())
	if hex.EncodeToString(cert.Subject.Compressed()) != identityHex {
		return g.reject("certificate subject does not match authenticated identity")
	}
	if err := g.verifyCert(ctx, &cert.Certificate); err != nil {
		return g.reject("certificate signature is invalid")
	}
	if err := g.verifyFields(ctx, cert, g.fields[typ]); err != nil {
		return g.reject(err.Error())
	}
	if cert.RevocationOutpoint == nil {
		return g.reject("certificate has no revocation outpoint")
	}
	if isSentinel(cert.RevocationOutpoint.String()) {
		if !g.unrev[typ] {
			return g.reject("unrevocable certificate is not allowed")
		}
		if err := g.remember(cacheKey{identityHex, typ, ""}, "", g.now().Add(g.recheck)); err != nil {
			return g.reject(err.Error())
		}
		g.verified.Add(1)
		return nil
	}
	outpoint := cert.RevocationOutpoint.String()
	key := cacheKey{identityHex, typ, outpoint}
	if g.freshAdmission(key, outpoint, g.now()) {
		g.verified.Add(1)
		return nil
	}
	spent, _, err := g.watch.Check(ctx, outpoint)
	expires := g.now().Add(g.recheck)
	if err != nil {
		g.checkError.Add(1)
		if g.strict {
			return g.reject("revocation check failed")
		}
		expires = g.now().Add(min(g.recheck, lazyRetry))
	} else if spent {
		return g.reject(ErrRevoked.Error())
	}
	if err := g.watch.Watch(outpoint, watchOwner); err != nil {
		return fmt.Errorf("%w: %v", ErrWatchUnavailable, err)
	}
	if err := g.remember(key, outpoint, expires); err != nil {
		g.unwatchIfUnused(outpoint)
		return fmt.Errorf("%w: %v", ErrWatchUnavailable, err)
	}
	g.verified.Add(1)
	return nil
}

func (g *Gate) verifyFields(ctx context.Context, cert *certificates.VerifiableCertificate, required []string) error {
	if len(required) == 0 {
		return nil
	}
	for _, name := range required {
		if _, ok := cert.Keyring[wallet.CertificateFieldNameUnder50Bytes(name)]; !ok {
			return fmt.Errorf("required certificate field is missing")
		}
	}
	if g.wallet == nil {
		return errors.New("certificate field verifier is unavailable")
	}
	fields, err := cert.DecryptFields(ctx, g.wallet, false, "")
	if err != nil {
		return fmt.Errorf("required certificate field cannot be decrypted")
	}
	for _, name := range required {
		if _, ok := fields[name]; !ok {
			return errors.New("required certificate field is missing")
		}
	}
	return nil
}

func (g *Gate) reject(reason string) error {
	return fmt.Errorf("%w: %s", ErrRefused, reason)
}

func isSentinel(outpoint string) bool {
	return outpoint == strings.Repeat("0", 64)+".0"
}
