package legacyshim

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/BSVanon/Anvil/internal/overlay/lookupguard"
	"github.com/BSVanon/Anvil/internal/overlay/overlayctx"
	"github.com/BSVanon/Anvil/internal/overlay/routeguard"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
)

// Query translates a legacy lookup body into the canonical lookup question,
// then reconstructs the legacy output metadata from each bounded BEEF.
func (s *Shim) Query(w http.ResponseWriter, r *http.Request) {
	s.writeSyncHeaders(w)
	t, body, ok := s.readGuarded(w, r, routeguard.LookupRoute, true)
	if !ok {
		return
	}
	defer t.Close()
	var q legacyLookupQuestion
	if err := json.Unmarshal(body, &q); err != nil {
		writeLegacyError(w, http.StatusBadRequest, "invalid query: "+err.Error())
		return
	}
	if q.Service == "" {
		writeLegacyError(w, http.StatusBadRequest, "service required")
		return
	}
	cursor, err := lookupguard.ParseCursor(r)
	if err != nil {
		writeLegacyError(w, http.StatusBadRequest, err.Error())
		return
	}

	question := &lookup.LookupQuestion{Service: q.Service, Query: q.Query}
	result, err := s.lookup(r, question, cursor)
	if err != nil {
		writeLegacyError(w, http.StatusBadRequest, err.Error())
		return
	}
	if r.Context().Err() != nil {
		return
	}
	legacy, err := s.canonicalToLegacyAnswer(r.Context(), q.Service, result.Answer)
	if err != nil {
		writeLegacyError(w, http.StatusInternalServerError, err.Error())
		return
	}
	encoded, err := capLegacyAnswer(legacy, &result, cursor)
	if err != nil {
		writeLegacyError(w, http.StatusInternalServerError, err.Error())
		return
	}
	lookupguard.WriteHeaders(w, result)
	t.Close()
	boundAnswerWrite(w, len(encoded))
	writeJSONBytes(w, http.StatusOK, encoded)
}

func (s *Shim) lookup(r *http.Request, question *lookup.LookupQuestion, cursor int) (lookupguard.Result, error) {
	ctx := overlayctx.ReadOnly(r.Context())
	if eng, ok := s.Engine.(*engine.Engine); ok {
		return lookupguard.Lookup(ctx, eng, question, cursor)
	}
	answer, err := s.Engine.Lookup(ctx, question)
	return lookupguard.Result{Answer: answer}, err
}

func capLegacyAnswer(answer *legacyLookupAnswer, result *lookupguard.Result, cursor int) ([]byte, error) {
	encoded, err := json.Marshal(answer)
	if err != nil || int64(len(encoded)) <= routeguard.LookupAllowance {
		return encoded, err
	}
	if len(answer.Outputs) == 0 {
		return nil, fmt.Errorf("lookup response is over %d bytes", routeguard.LookupAllowance)
	}

	all := answer.Outputs
	outputs := make([]legacyAdmittedOutput, 0, len(all))
	omitted := 0
	for i, output := range all {
		answer.Outputs = []legacyAdmittedOutput{output}
		single, marshalErr := json.Marshal(answer)
		if marshalErr != nil {
			return nil, marshalErr
		}
		if int64(len(single)) > routeguard.LookupAllowance {
			omitted++
			continue
		}
		candidate := append(outputs, output)
		answer.Outputs = candidate
		encoded, marshalErr = json.Marshal(answer)
		if marshalErr != nil {
			return nil, marshalErr
		}
		if int64(len(encoded)) > routeguard.LookupAllowance {
			answer.Outputs = outputs
			encoded, marshalErr = json.Marshal(answer)
			if marshalErr != nil {
				return nil, marshalErr
			}
			result.Truncated = true
			result.Next = cursor + i
			result.Omitted += omitted
			return encoded, nil
		}
		outputs = candidate
	}
	answer.Outputs = outputs
	encoded, err = json.Marshal(answer)
	if err != nil {
		return nil, err
	}
	result.Omitted += omitted
	if len(outputs) == 0 {
		result.Truncated = false
	}
	return encoded, nil
}
