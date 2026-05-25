package canonical

import (
	"encoding/json"
	"net/http"
)

// HealthReport is the JSON body of GET /health. The shape is fixed by
// conformance vector overlay.topicmanagement.1.
type HealthReport struct {
	Status  string         `json:"status"`            // "ok" | "degraded" | "error"
	Live    bool           `json:"live"`
	Ready   bool           `json:"ready"`
	Service ServiceSummary `json:"service"`
}

type ServiceSummary struct {
	Name               string `json:"name"`
	Network            string `json:"network"`
	TopicManagerCount  int    `json:"topicManagerCount"`
	LookupServiceCount int    `json:"lookupServiceCount"`
}

// LiveReport is the JSON body of GET /health/live. Fixed by vector
// overlay.topicmanagement.3.
type LiveReport struct {
	Live bool `json:"live"`
}

// ReadyReport is the JSON body of GET /health/ready. Fixed by vector
// overlay.topicmanagement.4.
type ReadyReport struct {
	Ready  bool   `json:"ready"`
	Status string `json:"status"`
}

func registerHealth(mux *http.ServeMux, cfg Config) {
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		handleHealth(w, cfg)
	})
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, r *http.Request) {
		handleLive(w)
	})
	mux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, r *http.Request) {
		handleReady(w, cfg)
	})
}

func handleHealth(w http.ResponseWriter, cfg Config) {
	ready := cfg.resolveReady()
	status := "ok"
	code := http.StatusOK
	if !ready {
		status = "degraded"
		code = http.StatusServiceUnavailable
	}
	body := HealthReport{
		Status: status,
		Live:   true,
		Ready:  ready,
		Service: ServiceSummary{
			Name:               cfg.NodeName,
			Network:            cfg.resolveNetwork(),
			TopicManagerCount:  cfg.resolveTopicCount(),
			LookupServiceCount: cfg.resolveLookupCount(),
		},
	}
	writeJSON(w, code, body)
}

func handleLive(w http.ResponseWriter) {
	// Process is alive iff this handler is executing, so always 200.
	writeJSON(w, http.StatusOK, LiveReport{Live: true})
}

func handleReady(w http.ResponseWriter, cfg Config) {
	ready := cfg.resolveReady()
	if !ready {
		// Vector overlay.topicmanagement.4 only covers the happy path.
		// 503 with status=error is the obvious choice when not ready; vectors
		// for that path will appear in later snapshots if they're added upstream.
		writeJSON(w, http.StatusServiceUnavailable, ReadyReport{Ready: false, Status: "error"})
		return
	}
	writeJSON(w, http.StatusOK, ReadyReport{Ready: true, Status: "ok"})
}

func writeJSON(w http.ResponseWriter, code int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}
