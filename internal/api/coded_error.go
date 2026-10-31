package api

import (
	"errors"
	"net/http"

	"github.com/BSVanon/Anvil/internal/messaging"
)

type codedError struct {
	Status      string `json:"status"`
	Code        string `json:"code"`
	Description string `json:"description"`
	Error       string `json:"error"`
}

func writeCodedError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, codedError{
		Status: "error", Code: code, Description: description, Error: description,
	})
}

// writeMessagingError reports whether the mapped error is an internal failure
// that the calling handler must log with its server logger.
func writeMessagingError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, messaging.ErrInvalidOriginNode):
		writeCodedError(w, http.StatusInternalServerError, "ERR_INTERNAL", "An internal error has occurred.")
		return true
	case errors.Is(err, messaging.ErrInvalidRecipient):
		writeCodedError(w, http.StatusBadRequest, "ERR_INVALID_RECIPIENT_KEY", "Recipient must be a valid compressed secp256k1 public key.")
	case errors.Is(err, messaging.ErrInvalidSender):
		writeCodedError(w, http.StatusBadRequest, "ERR_INVALID_SENDER", "Sender must be a valid compressed secp256k1 public key.")
	case errors.Is(err, messaging.ErrInvalidMessageID):
		writeCodedError(w, http.StatusBadRequest, "ERR_INVALID_MESSAGE_ID", "Invalid message ID.")
	case errors.Is(err, messaging.ErrInvalidMessageBox):
		writeCodedError(w, http.StatusBadRequest, "ERR_INVALID_MESSAGEBOX", "Invalid message box.")
	case errors.Is(err, messaging.ErrMessageBoxTooLarge):
		writeCodedError(w, http.StatusBadRequest, "ERR_MESSAGEBOX_TOO_LARGE", "Message box names must not exceed 128 bytes.")
	case errors.Is(err, messaging.ErrInvalidMessageBody):
		writeCodedError(w, http.StatusBadRequest, "ERR_INVALID_MESSAGE_BODY", "Invalid message body.")
	case errors.Is(err, messaging.ErrMessageBodyTooLarge):
		writeCodedError(w, http.StatusRequestEntityTooLarge, "ERR_MESSAGE_BODY_TOO_LARGE", "Message bodies must not exceed 1048576 bytes.")
	case errors.Is(err, messaging.ErrPairQuota):
		writeCodedError(w, http.StatusTooManyRequests, "ERR_SENDER_QUOTA_EXCEEDED", "Sender quota exceeded for this recipient.")
	case errors.Is(err, messaging.ErrInboxQuota):
		writeCodedError(w, http.StatusTooManyRequests, "ERR_INBOX_QUOTA_EXCEEDED", "Recipient inbox quota exceeded.")
	case errors.Is(err, messaging.ErrStoreFull):
		writeCodedError(w, http.StatusTooManyRequests, "ERR_NODE_STORE_FULL", "Node message store is full.")
	default:
		writeCodedError(w, http.StatusInternalServerError, "ERR_INTERNAL", "An internal error has occurred.")
		return true
	}
	return false
}
