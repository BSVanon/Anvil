package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/BSVanon/Anvil/internal/messaging"
)

// handleSendMessage handles POST /sendMessage — send a message to a recipient.
// The sender is the BRC-31-authenticated caller identity (canonical messagebox
// model); under the operator-token fallback the sender is the node identity.
// BRC-33 pattern.
func (s *Server) handleSendMessage(w http.ResponseWriter, r *http.Request) {
	if s.msgStore == nil {
		writeError(w, http.StatusServiceUnavailable, "messaging not enabled")
		return
	}

	caller, ok := s.resolveMessageCaller(w, r)
	if !ok {
		return
	}
	if !s.senderCertificateAllowed(r.Context(), caller.identityHex) {
		writeCodedError(w, http.StatusForbidden, "ERR_SENDER_CERTIFICATE_REQUIRED", "A valid sender certificate is required.")
		return
	}

	// JSON escaping can make a valid 1 MiB decoded body substantially larger on
	// the wire. Bound the request at the worst-case escape expansion, then apply
	// the exact decoded-body limit in messaging.Store.
	body, err := io.ReadAll(io.LimitReader(r.Body, 6*messaging.MaxMessageBodyBytes+(64<<10)))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read body")
		return
	}

	var req struct {
		Recipient  string `json:"recipient"`
		MessageBox string `json:"messageBox"`
		Body       string `json:"body"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}

	// Sender is the authenticated caller: their own identity under BRC-31, or
	// the node identity under the operator-token fallback. Either way the
	// forwarded message is signed by the node, so the hop is verifiable.
	sender := caller.identityHex

	msg := &messaging.Message{
		Sender:     sender,
		Recipient:  req.Recipient,
		MessageBox: req.MessageBox,
		Body:       req.Body,
	}

	id, forward, stored, err := s.sendHomeAware(msg)
	if err != nil {
		if writeMessagingError(w, err) {
			s.logger.Error("messagebox send failed", "error", err)
		}
		return
	}

	// Forward to mesh for cross-node delivery — skipped when the Home
	// Rule resolves the recipient as Home (the recipient's home node
	// already has it, so flooding the mesh would be pointless).
	// ForwardMessage signs with the node's identity key.
	sentTo := 0
	if forward && s.gossipMgr != nil {
		sentTo = s.gossipMgr.ForwardMessage(msg)
	}

	// A message that landed NOWHERE — nothing stored at this node,
	// and the forward (if attempted at all) reached zero peers — must
	// not come back 200. This only arises for an Elsewhere recipient
	// under forward_copy_ttl=0 (relay-only mode) with no peer currently
	// reachable; Home and Unadvertised always store here first.
	if !stored && sentTo == 0 {
		writeCodedError(w, http.StatusServiceUnavailable, "ERR_MESSAGE_UNDELIVERED",
			"The message could not be stored or forwarded to any peer.")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "success",
		"messageId": id,
	})
}

// MessagingPolicy bundles the Home/forward/operator-box messaging
// policy's API-layer configuration — the Home resolver, the per-copy
// forward TTL, and the operator-box-read switch — as one value, so
// Server and ServerConfig each carry a single field instead of three.
// A zero MessagingPolicy (every field nil) reproduces forwardCopyPolicy's and
// homeResolverOrDefault's documented "never wired up at all" legacy
// fallback, exactly as three separate nil fields did before.
type MessagingPolicy struct {
	Home                  messaging.HomeResolver
	ForwardCopyTTLSeconds *int64
	OperatorReadsAllBoxes *bool
	PrivateHomes          *messaging.PrivateHomeStore
	PrivateHomeCompatible func([]string) bool
}

// sendHomeAware applies the Home Rule's "API send" rows for msg's
// recipient:
//
//	Home         -> store at ttl_seconds (Send), never forward.
//	Unadvertised -> store at ttl_seconds (Send), forward (as today).
//	Elsewhere    -> store at forward_copy_ttl when it is > 0
//	                (SendElsewhere), or nothing when it is 0; forward
//	                either way.
//
// forwardCopyPolicy's legacy case (the Home Rule never wired up at all)
// reproduces the exact original behaviour: Send unconditionally, always
// forward.
//
// stored reports whether a row was actually persisted at THIS node —
// false only for Elsewhere with forward_copy_ttl=0, where
// SendElsewhere deliberately persists nothing (relay-only). The caller
// uses it together with how many peers the forward actually reached to
// decide whether the message landed nowhere at all.
func (s *Server) sendHomeAware(msg *messaging.Message) (id string, forward bool, stored bool, err error) {
	ttl, store, legacy := s.forwardCopyPolicy()
	if legacy {
		id, err = s.msgStore.Send(msg, s.identityPub)
		return id, true, err == nil, err
	}
	res, resErr := s.homeResolverOrDefault().Resolve(msg.Recipient)
	if resErr != nil {
		s.logger.Debug("home resolution failed, treating recipient as unadvertised", "error", resErr)
		res = messaging.Resolution{State: messaging.Unadvertised}
	}
	switch res.State {
	case messaging.Home:
		id, err = s.msgStore.Send(msg, s.identityPub)
		forward = false
		if s.messagingPolicy.PrivateHomes != nil {
			if _, ok, claimErr := s.messagingPolicy.PrivateHomes.Current(msg.Recipient); claimErr == nil && ok {
				forward = res.HasOtherHost
			}
		}
		return id, forward, err == nil, err
	case messaging.Elsewhere:
		id, err = s.msgStore.SendElsewhere(msg, s.identityPub, ttl, store)
		return id, true, store && err == nil, err
	default: // Unadvertised
		id, err = s.msgStore.Send(msg, s.identityPub)
		return id, true, err == nil, err
	}
}

// homeResolverOrDefault mirrors gossip.Manager's helper of the same
// purpose: nil means the Home Rule was never wired up, which always
// answers Unadvertised — "when this node doesn't host the topic",
// and today's behaviour.
func (s *Server) homeResolverOrDefault() messaging.HomeResolver {
	if s.messagingPolicy.Home != nil {
		return s.messagingPolicy.Home
	}
	return messaging.AlwaysUnadvertised
}

// forwardCopyPolicy mirrors gossip.Manager's helper of the same name:
// forwardCopyTTLSeconds nil means the Home/forward policy was never
// wired up at all (legacy=true), which the caller must handle by
// reproducing the exact original behaviour rather than treating a bare
// zero as an explicit forward_copy_ttl=0.
func (s *Server) forwardCopyPolicy() (ttlSeconds int64, store bool, legacy bool) {
	if s.messagingPolicy.ForwardCopyTTLSeconds == nil {
		return 0, false, true
	}
	ttl := *s.messagingPolicy.ForwardCopyTTLSeconds
	return ttl, ttl > 0, false
}

// handleListMessages handles POST /listMessages — retrieve messages for the
// caller. Under BRC-31 the query is strictly scoped to the authenticated
// identity (you can only read your own inbox); under the operator-token
// fallback the recipient may be supplied in the body (defaulting to the node).
func (s *Server) handleListMessages(w http.ResponseWriter, r *http.Request) {
	if s.msgStore == nil {
		writeError(w, http.StatusServiceUnavailable, "messaging not enabled")
		return
	}

	caller, ok := s.resolveMessageCaller(w, r)
	if !ok {
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read body")
		return
	}

	var req struct {
		Recipient  string          `json:"recipient"`
		MessageBox string          `json:"messageBox"`
		Limit      json.RawMessage `json:"limit"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}
	if req.MessageBox == "" {
		writeCodedError(w, http.StatusBadRequest, "ERR_INVALID_MESSAGEBOX", "Invalid message box.")
		return
	}
	if len(req.MessageBox) > messaging.MaxMessageBoxBytes {
		writeCodedError(w, http.StatusBadRequest, "ERR_MESSAGEBOX_TOO_LARGE", "Message box names must not exceed 128 bytes.")
		return
	}
	limit := 0
	if len(req.Limit) != 0 {
		if err := json.Unmarshal(req.Limit, &limit); err != nil || limit < 0 {
			writeCodedError(w, http.StatusBadRequest, "ERR_INVALID_LIMIT", "limit must be a non-negative integer")
			return
		}
	}
	if limit > 100 {
		limit = 100
	}
	recipient, ok := s.scopedRecipient(w, caller, req.Recipient)
	if !ok {
		return
	}

	msgs, err := s.msgStore.ListN(recipient, req.MessageBox, limit)
	if err != nil {
		if writeMessagingError(w, err) {
			s.logger.Error("messagebox list failed", "error", err)
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "success",
		"messages": msgs,
	})
}

// handleAcknowledgeMessage handles POST /acknowledgeMessage — delete messages
// after receipt. Under BRC-31 deletion is strictly scoped to the authenticated
// identity's inbox; under the operator-token fallback the recipient may be
// supplied in the body (defaulting to the node).
func (s *Server) handleAcknowledgeMessage(w http.ResponseWriter, r *http.Request) {
	if s.msgStore == nil {
		writeError(w, http.StatusServiceUnavailable, "messaging not enabled")
		return
	}

	caller, ok := s.resolveMessageCaller(w, r)
	if !ok {
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read body")
		return
	}

	var req struct {
		Recipient  string          `json:"recipient"`
		MessageIDs json.RawMessage `json:"messageIds"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}
	if len(req.MessageIDs) == 0 {
		writeCodedError(w, http.StatusBadRequest, "ERR_MESSAGE_ID_REQUIRED", "Please provide the ID of the message(s) to acknowledge!")
		return
	}
	var rawIDs []json.RawMessage
	if err := json.Unmarshal(req.MessageIDs, &rawIDs); err != nil {
		writeCodedError(w, http.StatusBadRequest, "ERR_INVALID_MESSAGE_ID", "Message IDs must be an array of at most 1000 non-empty strings.")
		return
	}
	if len(rawIDs) == 0 {
		writeCodedError(w, http.StatusBadRequest, "ERR_MESSAGE_ID_REQUIRED", "Please provide the ID of the message(s) to acknowledge!")
		return
	}
	if len(rawIDs) > 1000 {
		writeCodedError(w, http.StatusBadRequest, "ERR_INVALID_MESSAGE_ID", "Message IDs must be an array of at most 1000 non-empty strings.")
		return
	}
	uniqueIDs := make([]string, 0, len(rawIDs))
	seenIDs := make(map[string]struct{}, len(rawIDs))
	for _, rawID := range rawIDs {
		var id string
		if err := json.Unmarshal(rawID, &id); err != nil ||
			strings.TrimSpace(id) == "" || len(id) > messaging.MaxMessageIDBytes {
			writeCodedError(w, http.StatusBadRequest, "ERR_INVALID_MESSAGE_ID", "Message IDs must be non-empty and at most 256 bytes.")
			return
		}
		if _, seen := seenIDs[id]; seen {
			continue
		}
		seenIDs[id] = struct{}{}
		uniqueIDs = append(uniqueIDs, id)
	}
	recipient, ok := s.scopedRecipient(w, caller, req.Recipient)
	if !ok {
		return
	}

	n, err := s.msgStore.Acknowledge(recipient, uniqueIDs)
	if err != nil {
		if writeMessagingError(w, err) {
			s.logger.Error("messagebox acknowledge failed", "error", err)
		}
		return
	}
	if s.gossipMgr != nil {
		s.gossipMgr.BroadcastHomeAck(recipient, uniqueIDs)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":       "success",
		"acknowledged": n,
	})
}
