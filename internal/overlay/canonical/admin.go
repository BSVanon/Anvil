package canonical

import (
	"encoding/json"
	"net/http"
)

// AdminConfigReport is the JSON body of GET /admin/config. Shape fixed by
// conformance vectors overlay.topicmanagement.5 and .6.
type AdminConfigReport struct {
	AdminIdentityKey *string `json:"adminIdentityKey"`
	NodeName         string  `json:"nodeName"`
}

func registerAdminConfig(mux *http.ServeMux, cfg Config) {
	mux.HandleFunc("GET /admin/config", func(w http.ResponseWriter, r *http.Request) {
		handleAdminConfig(w, cfg)
	})
}

func handleAdminConfig(w http.ResponseWriter, cfg Config) {
	var key *string
	if cfg.AdminIdentityKey != "" {
		k := cfg.AdminIdentityKey
		key = &k
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(AdminConfigReport{
		AdminIdentityKey: key,
		NodeName:         cfg.NodeName,
	})
}
