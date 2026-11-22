package certgate

import (
	"container/list"
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

const restoredAdmissionType = "private-home-restored"

func (g *Gate) freshAdmission(key cacheKey, outpoint string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	adm, ok := g.cache[key]
	return ok && adm.outpoint == outpoint && now.Before(adm.expires)
}

// Admitted reports whether identity has any current verified certificate.
// Expired entries are rechecked before they are used again.
func (g *Gate) Admitted(ctx context.Context, identity string) bool {
	g.mu.Lock()
	var due []struct {
		key cacheKey
		adm admission
	}
	now := g.now()
	for key, adm := range g.cache {
		if key.identity != identity {
			continue
		}
		if now.Before(adm.expires) || adm.outpoint == "" {
			g.mu.Unlock()
			return true
		}
		due = append(due, struct {
			key cacheKey
			adm admission
		}{key, adm})
	}
	g.mu.Unlock()
	for _, item := range due {
		spent, _, err := g.watch.Check(ctx, item.adm.outpoint)
		if err != nil {
			g.checkError.Add(1)
			if g.strict {
				if g.reschedulePinned(item.key, item.adm, now.Add(lazyRetry)) {
					return true
				}
				g.forget(item.key)
				continue
			}
			_ = g.remember(item.key, item.adm.outpoint, now.Add(min(g.recheck, lazyRetry)))
			return true
		}
		if spent {
			g.revokeOutpoint(item.adm.outpoint)
			continue
		}
		_ = g.remember(item.key, item.adm.outpoint, now.Add(g.recheck))
		return true
	}
	return false
}

// AdmissionOutpoint returns one current admission's revocation outpoint. An
// empty outpoint with ok=true represents an explicitly allowed unrevocable
// certificate.
func (g *Gate) AdmissionOutpoint(ctx context.Context, identity string) (string, bool) {
	identity = strings.ToLower(identity)
	if !g.Admitted(ctx, identity) {
		return "", false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for element := g.order.Back(); element != nil; element = element.Prev() {
		key := element.Value.(cacheKey)
		admission := g.cache[key]
		if key.identity == identity && (admission.outpoint == "" || g.now().Before(admission.expires)) {
			return admission.outpoint, true
		}
	}
	return "", false
}

// AdmissionMatches closes the write-time race between fetching an admission
// outpoint and persisting a gated object. If revocation removed the cache entry
// in between, the caller must undo the write.
func (g *Gate) AdmissionMatches(identity, outpoint string) bool {
	identity = strings.ToLower(identity)
	g.mu.Lock()
	defer g.mu.Unlock()
	pinnedOutpoint, pinned := g.pinned[identity]
	if !pinned || pinnedOutpoint != outpoint {
		return false
	}
	for key, admission := range g.cache {
		if key.identity == identity && admission.outpoint == outpoint {
			return true
		}
	}
	return false
}

// RestoreAdmission rebuilds the revocation check/watch for a persisted claim.
// It does not trust the stored binding as proof: revocable outpoints are checked
// before the claim may remain active.
func (g *Gate) RestoreAdmission(ctx context.Context, identity, outpoint string) error {
	identity = strings.ToLower(identity)
	raw, err := hex.DecodeString(identity)
	if err != nil {
		return ErrRefused
	}
	if _, err := ec.ParsePubKey(raw); err != nil {
		return ErrRefused
	}
	key := cacheKey{identity: identity, typ: restoredAdmissionType, outpoint: outpoint}
	if outpoint == "" {
		if err := g.remember(key, "", g.now().Add(g.recheck)); err != nil {
			return err
		}
		_, err := g.PinAdmission(identity, "")
		return err
	}
	spent, _, err := g.watch.Check(ctx, outpoint)
	expires := g.now().Add(g.recheck)
	if err != nil {
		g.checkError.Add(1)
		if g.strict {
			return err
		}
		expires = g.now().Add(min(g.recheck, lazyRetry))
	} else if spent {
		return ErrRevoked
	}
	if err := g.watch.Watch(outpoint, watchOwner); err != nil {
		return err
	}
	if err := g.remember(key, outpoint, expires); err != nil {
		g.unwatchIfUnused(outpoint)
		return err
	}
	if _, err := g.PinAdmission(identity, outpoint); err != nil {
		g.forget(key)
		return err
	}
	return nil
}

func (g *Gate) remember(key cacheKey, outpoint string, expires time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if old, ok := g.cache[key]; ok {
		if old.outpoint != outpoint {
			g.removeOutpointKey(old.outpoint, key)
		}
	} else {
		for len(g.cache) >= maxAdmissions {
			var victim *list.Element
			for element := g.order.Front(); element != nil; element = element.Next() {
				oldKey := element.Value.(cacheKey)
				old := g.cache[oldKey]
				pinnedOutpoint, pinned := g.pinned[oldKey.identity]
				if !pinned || pinnedOutpoint != old.outpoint {
					victim = element
					break
				}
			}
			if victim == nil {
				return ErrAdmissionFull
			}
			g.removeAdmissionLocked(victim.Value.(cacheKey))
		}
		element := g.order.PushBack(key)
		g.orderByKey[key] = element
	}
	g.cache[key] = admission{outpoint: outpoint, expires: expires}
	if outpoint != "" {
		if g.byOutpoint[outpoint] == nil {
			g.byOutpoint[outpoint] = map[cacheKey]struct{}{}
		}
		g.byOutpoint[outpoint][key] = struct{}{}
	}
	return nil
}

func (g *Gate) forget(key cacheKey) {
	g.mu.Lock()
	defer g.mu.Unlock()
	adm, ok := g.cache[key]
	if !ok {
		return
	}
	pinnedOutpoint, hasPin := g.pinned[key.identity]
	if hasPin && pinnedOutpoint == adm.outpoint {
		return
	}
	g.removeAdmissionLocked(key)
}

func (g *Gate) reschedulePinned(key cacheKey, expected admission, expires time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	adm, ok := g.cache[key]
	if !ok || adm != expected {
		return false
	}
	pinnedOutpoint, pinned := g.pinned[key.identity]
	if !pinned || pinnedOutpoint != adm.outpoint {
		return false
	}
	adm.expires = expires
	g.cache[key] = adm
	return true
}

func (g *Gate) removeAdmissionLocked(key cacheKey) {
	adm, ok := g.cache[key]
	if !ok {
		return
	}
	delete(g.cache, key)
	if element := g.orderByKey[key]; element != nil {
		g.order.Remove(element)
		delete(g.orderByKey, key)
	}
	g.removeOutpointKey(adm.outpoint, key)
}

func (g *Gate) removeOutpointKey(outpoint string, key cacheKey) {
	keys := g.byOutpoint[outpoint]
	delete(keys, key)
	if outpoint != "" && len(keys) == 0 {
		delete(g.byOutpoint, outpoint)
		g.watch.Unwatch(outpoint, watchOwner)
	}
}

// PinAdmission keeps the admission and its watch until the private-home claim
// that uses it is removed. The returned value is the previous pinned outpoint.
func (g *Gate) PinAdmission(identity, outpoint string) (string, error) {
	identity = strings.ToLower(identity)
	g.mu.Lock()
	defer g.mu.Unlock()
	found := false
	for key, admission := range g.cache {
		if key.identity == identity && admission.outpoint == outpoint {
			found = true
			break
		}
	}
	if !found {
		return "", fmt.Errorf("%w: admission is no longer current", ErrWatchUnavailable)
	}
	if outpoint != "" {
		if err := g.watch.Watch(outpoint, watchOwner); err != nil {
			return "", fmt.Errorf("%w: %v", ErrWatchUnavailable, err)
		}
	}
	previous, existed := g.pinned[identity]
	if !existed && len(g.pinned) >= maxAdmissions {
		return "", ErrAdmissionFull
	}
	g.pinned[identity] = outpoint
	return previous, nil
}

// UnpinAdmission releases a private-home claim's cache protection.
func (g *Gate) UnpinAdmission(identity string) {
	g.mu.Lock()
	delete(g.pinned, strings.ToLower(identity))
	g.mu.Unlock()
}

func (g *Gate) unwatchIfUnused(outpoint string) {
	if outpoint == "" {
		return
	}
	g.mu.Lock()
	if len(g.byOutpoint[outpoint]) == 0 {
		g.watch.Unwatch(outpoint, watchOwner)
	}
	g.mu.Unlock()
}

// OnRevoke installs one hook for a use. Replacing a hook is intentional.
func (g *Gate) OnRevoke(use string, hook func(identity string)) {
	g.mu.Lock()
	if hook == nil {
		delete(g.hooks, use)
	} else {
		g.hooks[use] = hook
	}
	g.mu.Unlock()
}

// SetSpendVerifier supplies the candidate-spend verifier used by the watcher.
func (g *Gate) SetSpendVerifier(fn func(context.Context, string, string) error) {
	g.mu.Lock()
	g.verifySpend = fn
	g.mu.Unlock()
}

func (g *Gate) onCandidateSpend(outpoint, spendingTxid string) {
	g.mu.Lock()
	verify := g.verifySpend
	g.mu.Unlock()
	if verify == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if verify(ctx, outpoint, spendingTxid) == nil {
			g.revokeOutpoint(outpoint)
		}
	}()
}

func (g *Gate) revokeOutpoint(outpoint string) {
	g.mu.Lock()
	keys := g.byOutpoint[outpoint]
	identities := map[string]struct{}{}
	for key := range keys {
		identities[key.identity] = struct{}{}
	}
	for key := range keys {
		g.removeAdmissionLocked(key)
	}
	for identity, pinnedOutpoint := range g.pinned {
		if pinnedOutpoint == outpoint {
			delete(g.pinned, identity)
		}
	}
	hooks := g.hooksLocked()
	if len(identities) > 0 {
		_ = g.watch.Watch(outpoint, watchOwner)
	}
	g.mu.Unlock()
	for identity := range identities {
		for _, hook := range hooks {
			hook(identity)
		}
	}
	g.unwatchIfUnused(outpoint)
	for range identities {
		g.revoked.Add(1)
	}
}

func (g *Gate) hooksLocked() []func(string) {
	hooks := make([]func(string), 0, len(g.hooks))
	for _, hook := range g.hooks {
		hooks = append(hooks, hook)
	}
	return hooks
}

// Stats returns the stable counters exposed by /stats.
func (g *Gate) Stats() map[string]int64 {
	return map[string]int64{
		"certgate_verified":     g.verified.Load(),
		"certgate_refused":      g.refused.Load(),
		"certgate_revoked":      g.revoked.Load(),
		"certgate_check_errors": g.checkError.Load(),
	}
}
