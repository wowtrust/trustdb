package sdk

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/wowtrust/trustdb/internal/trusterr"
)

type Error struct {
	Op         string
	URL        string
	StatusCode int
	Code       string
	Message    string
	Err        error
	retryable  bool
}

func (e *Error) Error() string {
	prefix := e.Op
	if e.URL != "" {
		prefix += " " + e.URL
	}
	switch {
	case e.Err != nil && e.Message != "":
		return fmt.Sprintf("%s: %s: %v", prefix, e.Message, e.Err)
	case e.Err != nil:
		return fmt.Sprintf("%s: %v", prefix, e.Err)
	case e.Code != "" && e.Message != "":
		return fmt.Sprintf("%s: %s: %s", prefix, e.Code, e.Message)
	case e.Message != "":
		return fmt.Sprintf("%s: %s", prefix, e.Message)
	case e.StatusCode != 0:
		return fmt.Sprintf("%s: http status %d", prefix, e.StatusCode)
	default:
		return prefix
	}
}

func (e *Error) Unwrap() error {
	return e.Err
}

func asSDKError(err error) (*Error, bool) {
	var sdkErr *Error
	if errors.As(err, &sdkErr) {
		return sdkErr, true
	}
	return nil, false
}

func IsNotFound(err error) bool {
	var sdkErr *Error
	return errors.As(err, &sdkErr) &&
		(sdkErr.StatusCode == http.StatusNotFound || sdkErr.Code == string(trusterr.CodeNotFound))
}

func IsUnavailable(err error) bool {
	var sdkErr *Error
	if !errors.As(err, &sdkErr) {
		return false
	}
	return sdkErr.StatusCode == http.StatusNotFound ||
		sdkErr.StatusCode == http.StatusPreconditionFailed ||
		sdkErr.Code == string(trusterr.CodeNotFound) ||
		sdkErr.Code == string(trusterr.CodeFailedPrecondition)
}

func retryableEndpointError(err error) bool {
	var sdkErr *Error
	if !errors.As(err, &sdkErr) {
		// Custom transports do not have a shared typed error contract. Preserve
		// failover for their opaque errors rather than treating them as terminal.
		return true
	}
	if sdkErr.retryable {
		return true
	}
	if sdkErr.StatusCode == 0 && sdkErr.Code == "" && sdkErr.Err != nil {
		return true
	}
	switch sdkErr.StatusCode {
	case http.StatusRequestTimeout,
		http.StatusTooManyRequests,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}
