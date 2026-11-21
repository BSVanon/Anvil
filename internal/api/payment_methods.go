package api

// paymentMethods reports the payment schemes this server advertises. The
// challenge/proof scheme is visible only on a gate that can actually run it.
func (s *Server) paymentMethods() []string {
	methods := []string{"BRC-121", "X-Bsv-Payment"}
	if s.paymentGate != nil && !s.paymentGate.noProofScheme {
		methods = append(methods, "X402-Challenge/Proof (deprecated)")
	}
	return methods
}
