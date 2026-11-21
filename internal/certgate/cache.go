package certgate

import (
	"context"
	"time"
)

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
				g.forget(item.key)
				continue
			}
			g.remember(item.key, item.adm.outpoint, now.Add(min(g.recheck, lazyRetry)))
			return true
		}
		if spent {
			g.revokeOutpoint(item.adm.outpoint)
			continue
		}
		g.remember(item.key, item.adm.outpoint, now.Add(g.recheck))
		return true
	}
	return false
}

func (g *Gate) remember(key cacheKey, outpoint string, expires time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	_, existed := g.cache[key]
	if old, ok := g.cache[key]; ok {
		if old.outpoint != outpoint {
			g.removeOutpointKey(old.outpoint, key)
		}
	} else {
		g.order = append(g.order, key)
	}
	for !existed && len(g.cache) >= maxAdmissions && len(g.order) > 0 {
		oldKey := g.order[0]
		g.order = g.order[1:]
		old, ok := g.cache[oldKey]
		if !ok {
			continue
		}
		delete(g.cache, oldKey)
		g.removeOutpointKey(old.outpoint, oldKey)
	}
	g.cache[key] = admission{outpoint: outpoint, expires: expires}
	if outpoint != "" {
		if g.byOutpoint[outpoint] == nil {
			g.byOutpoint[outpoint] = map[cacheKey]struct{}{}
		}
		g.byOutpoint[outpoint][key] = struct{}{}
	}
}

func (g *Gate) forget(key cacheKey) {
	g.mu.Lock()
	if adm, ok := g.cache[key]; ok {
		delete(g.cache, key)
		g.removeOutpointKey(adm.outpoint, key)
	}
	g.mu.Unlock()
}

func (g *Gate) removeOutpointKey(outpoint string, key cacheKey) {
	keys := g.byOutpoint[outpoint]
	delete(keys, key)
	if outpoint != "" && len(keys) == 0 {
		delete(g.byOutpoint, outpoint)
		g.watch.Unwatch(outpoint, watchOwner)
	}
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
		delete(g.cache, key)
	}
	delete(g.byOutpoint, outpoint)
	g.watch.Unwatch(outpoint, watchOwner)
	hooks := make([]func(string), 0, len(g.hooks))
	for _, hook := range g.hooks {
		hooks = append(hooks, hook)
	}
	g.mu.Unlock()
	for identity := range identities {
		g.revoked.Add(1)
		for _, hook := range hooks {
			hook(identity)
		}
	}
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
