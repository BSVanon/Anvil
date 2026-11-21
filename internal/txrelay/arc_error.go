package txrelay

import "fmt"

// ARCHTTPError is an ARC answer whose HTTP status is neither 200 nor 201. ARC
// answers a transaction it refuses with the refusal's own code as the status
// (460 to 475 for a transaction it judges invalid, pkg/api/status.go), so a
// caller can tell a refused transaction from a failed request. Its text is
// the text Submit has always returned for such an answer.
type ARCHTTPError struct {
	StatusCode int
	Body       string
}

func (e *ARCHTTPError) Error() string {
	return fmt.Sprintf("ARC returned %d: %s", e.StatusCode, e.Body)
}
