package osint

import "errors"

// ErrAPIKeyMissing is returned when a required API key is not configured.
// Callers should surface a user-friendly message pointing to the Settings → API Keys menu.
var ErrAPIKeyMissing = errors.New("API key not configured")

// ErrRateLimited is returned when an external service responds with HTTP 429.
// Callers should back off and retry, or inform the user.
var ErrRateLimited = errors.New("rate limited by external service")

// ErrServiceUnavailable is returned on persistent HTTP 5xx errors, network
// failures, or when a required external tool (e.g. sherlock) is not installed.
var ErrServiceUnavailable = errors.New("external service unavailable")

// ErrNotFound is returned when a resource exists but the target has no results
// (e.g. no breaches found, no social profile found). Distinct from an error.
var ErrNotFound = errors.New("no results found")
