package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/BSVanon/Anvil/internal/envelope"
)

// findCatalogRedirect scans anvil:catalog envelopes (newest-first) for a
// matching app name and returns its content_origin, or "" if none. A
// private catalog entry is always skipped: handleAppRedirect and its
// fallback variant are mounted with no authentication at all (cors only, no
// openRead) — a private listing's existence or content_origin must never be
// reachable here, for any caller.
func findCatalogRedirect(envs []*envelope.Envelope, appName string) string {
	for _, env := range envs {
		if env.Private {
			continue
		}
		var listing struct {
			Name          string `json:"name"`
			ContentOrigin string `json:"content_origin"`
		}
		if err := json.Unmarshal([]byte(env.Payload), &listing); err != nil {
			continue
		}
		if strings.EqualFold(listing.Name, appName) && listing.ContentOrigin != "" {
			return listing.ContentOrigin
		}
	}
	return ""
}

// handleAppRedirect serves /app/{name} — redirects to the latest inscription
// for a named app from the anvil:catalog topic. Every node in the mesh can
// serve this because the catalog gossips across all peers.
func (s *Server) handleAppRedirect(w http.ResponseWriter, r *http.Request) {
	appName := r.PathValue("name")
	if appName == "" {
		writeError(w, http.StatusBadRequest, "app name required")
		return
	}

	if s.envelopeStore == nil {
		writeError(w, http.StatusServiceUnavailable, "no envelope store")
		return
	}

	envs, err := s.envelopeStore.QueryExactTopic("anvil:catalog", 100)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "catalog query failed")
		return
	}

	if origin := findCatalogRedirect(envs, appName); origin != "" {
		target := "/content/" + origin
		if s.publicURL != "" {
			target = s.publicURL + target
		}
		http.Redirect(w, r, target, http.StatusFound)
		return
	}

	writeError(w, http.StatusNotFound, fmt.Sprintf("app %q not found in catalog or has no content_origin", appName))
}

// handleAppRedirectWithFallback is like handleAppRedirect but falls back
// to a configured content origin when the catalog has no matching entry.
// Used by /explorer to survive catalog expiry.
func (s *Server) handleAppRedirectWithFallback(w http.ResponseWriter, r *http.Request, fallbackOrigin string) {
	appName := r.PathValue("name")

	if s.envelopeStore != nil {
		envs, err := s.envelopeStore.QueryExactTopic("anvil:catalog", 100)
		if err == nil {
			if origin := findCatalogRedirect(envs, appName); origin != "" {
				target := "/content/" + origin
				if s.publicURL != "" {
					target = s.publicURL + target
				}
				http.Redirect(w, r, target, http.StatusFound)
				return
			}
		}
	}

	// Fall back to configured origin
	if fallbackOrigin != "" {
		target := "/content/" + fallbackOrigin
		if s.publicURL != "" {
			target = s.publicURL + target
		}
		http.Redirect(w, r, target, http.StatusFound)
		return
	}

	writeError(w, http.StatusNotFound, "explorer not configured")
}
