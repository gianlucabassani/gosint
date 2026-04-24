package osint

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/time/rate"
)

// RetryableHTTPClient is a shared HTTP client that handles rate limiting,
// automatic retries with exponential backoff, and context propagation.
// All OSINT modules share an instance of this rather than creating raw http.Client.
type RetryableHTTPClient struct {
	client     *http.Client
	maxRetries int
	retryDelay time.Duration
	rateLimit  *rate.Limiter
}

// NewRetryableHTTPClient creates a client with sensible OSINT defaults:
//   - 15 second per-request timeout
//   - 3 retries with exponential backoff starting at 1s
//   - 1 request/second rate limit (respects most free API tiers)
func NewRetryableHTTPClient() *RetryableHTTPClient {
	return &RetryableHTTPClient{
		client:     &http.Client{Timeout: 15 * time.Second},
		maxRetries: 3,
		retryDelay: 1 * time.Second,
		rateLimit:  rate.NewLimiter(rate.Limit(1), 3), // 1 req/s, burst of 3
	}
}

// NewRetryableHTTPClientWithOptions creates a client with custom parameters.
// rps = requests per second; burst = token bucket burst size.
func NewRetryableHTTPClientWithOptions(timeout time.Duration, maxRetries int, retryDelay time.Duration, rps float64, burst int) *RetryableHTTPClient {
	return &RetryableHTTPClient{
		client:     &http.Client{Timeout: timeout},
		maxRetries: maxRetries,
		retryDelay: retryDelay,
		rateLimit:  rate.NewLimiter(rate.Limit(rps), burst),
	}
}

// Get performs a rate-limited, retrying GET request. The request is tied to
// ctx — cancellation propagates to the in-flight HTTP call immediately.
// headers is an optional map of extra request headers (e.g. API auth headers).
func (c *RetryableHTTPClient) Get(ctx context.Context, url string, headers map[string]string) (*http.Response, error) {
	// Wait for the rate limiter token. This blocks until a slot is available
	// or the context is cancelled.
	if err := c.rateLimit.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter: %w", ctx.Err())
	}

	var lastErr error
	for attempt := 0; attempt < c.maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("building request: %w", err)
		}

		// Apply caller-supplied headers
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		req.Header.Set("User-Agent", "GOSINT-OSINT/1.0")

		resp, err := c.client.Do(req)
		if err != nil {
			// Context cancelled — stop immediately, don't retry
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = err
		} else {
			switch resp.StatusCode {
			case http.StatusTooManyRequests:
				resp.Body.Close()
				lastErr = ErrRateLimited
			case http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusGatewayTimeout:
				resp.Body.Close()
				lastErr = fmt.Errorf("%w (HTTP %d)", ErrServiceUnavailable, resp.StatusCode)
			default:
				// Any other status code is returned to the caller to interpret
				return resp, nil
			}
		}

		// Don't sleep after the last attempt
		if attempt < c.maxRetries-1 {
			backoff := c.retryDelay * time.Duration(attempt+1) // linear backoff: 1s, 2s, 3s
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}
	}

	return nil, fmt.Errorf("all %d attempts failed: %w", c.maxRetries, lastErr)
}
