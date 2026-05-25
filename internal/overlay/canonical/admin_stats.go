package canonical

import (
	"encoding/json"
	"net/http"
	"strings"
)

// AdminStatsResponse is the JSON body of GET /admin/stats. Shape fixed by
// conformance vector overlay.topicmanagement.8.
type AdminStatsResponse struct {
	Status string         `json:"status"` // "success"
	Data   AdminStatsData `json:"data"`
}

type AdminStatsData struct {
	NodeName       string   `json:"nodeName"`
	Network        string   `json:"network"`
	TopicManagers  []string `json:"topicManagers"`
	LookupServices []string `json:"lookupServices"`
}

func registerAdminStats(mux *http.ServeMux, cfg Config) {
	mux.HandleFunc("GET /admin/stats", func(w http.ResponseWriter, r *http.Request) {
		handleAdminStats(w, r, cfg)
	})
}

func handleAdminStats(w http.ResponseWriter, r *http.Request, cfg Config) {
	// Vectors .7, .8: Bearer token check.
	if !bearerAuthOK(r, cfg.AdminBearerToken) {
		writeStructuredError(w, http.StatusUnauthorized, "UNAUTHORIZED")
		return
	}

	body := AdminStatsResponse{
		Status: "success",
		Data: AdminStatsData{
			NodeName:       cfg.NodeName,
			Network:        cfg.resolveNetwork(),
			TopicManagers:  cfg.resolveTopicNames(),
			LookupServices: cfg.resolveLookupNames(),
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(body)
}

// bearerAuthOK returns true iff the request's Authorization header carries a
// Bearer token matching wantToken. Empty wantToken always returns false
// (admin routes disabled by config).
func bearerAuthOK(r *http.Request, wantToken string) bool {
	if wantToken == "" {
		return false
	}
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return false
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	return auth[len(prefix):] == wantToken
}

// writeStructuredError is the canonical error envelope shape used by
// /admin/stats and /arc-ingest. Body: {status: "error", code: <code>}.
func writeStructuredError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "error",
		"code":   code,
	})
}
