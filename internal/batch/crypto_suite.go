package batch

import "github.com/wowtrust/trustdb/v2/internal/cryptosuite"

// CryptoSuite returns the immutable suite bound to this service instance.
// Transports use it to parse suite-specific request fields without guessing
// algorithms from input length or accepting legacy aliases.
func (s *Service) CryptoSuite() cryptosuite.ID {
	if s == nil {
		return ""
	}
	return s.suiteID
}
