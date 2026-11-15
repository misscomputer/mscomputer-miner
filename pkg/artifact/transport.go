// Copyright (c) 2026 Ms. Computer. All rights reserved.
// SPDX-License-Identifier: LicenseRef-MsComputer-Miner

package artifact

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultS3RequestTimeout = 2 * time.Minute
	DefaultS3MaxAttempts    = 3
	DefaultS3MaxObjectBytes = int64(2 << 30)

	maxS3Attempts       = 10
	maxS3ErrorBodyBytes = int64(4 << 10)
	maxS3RetryDelay     = 5 * time.Second
	defaultRetryDelay   = 200 * time.Millisecond
)

// S3ErrorKind is a stable, credential-free classification for an S3-compatible
// failure. Callers should use errors.As rather than matching provider text.
type S3ErrorKind string

const (
	S3ErrorAuthentication S3ErrorKind = "authentication"
	S3ErrorConflict       S3ErrorKind = "conflict"
	S3ErrorInvalidRequest S3ErrorKind = "invalid_request"
	S3ErrorNotFound       S3ErrorKind = "not_found"
	S3ErrorPermission     S3ErrorKind = "permission"
	S3ErrorResponseTooBig S3ErrorKind = "response_too_large"
	S3ErrorThrottled      S3ErrorKind = "throttled"
	S3ErrorTimeout        S3ErrorKind = "timeout"
	S3ErrorTransport      S3ErrorKind = "transport"
	S3ErrorUnavailable    S3ErrorKind = "unavailable"
	S3ErrorUnexpected     S3ErrorKind = "unexpected_status"
)

// S3Error deliberately omits request URLs, response messages, headers, and
// the underlying transport error. Those values can contain provider
// reflections or signed authorization material.
type S3Error struct {
	Operation     string
	Key           string
	Kind          S3ErrorKind
	StatusCode    int
	ServiceCode   string
	Retryable     bool
	BodyTruncated bool
}

func (e *S3Error) Error() string {
	key := safeErrorKey(e.Key)
	if e.StatusCode != 0 {
		serviceCode := ""
		if e.ServiceCode != "" {
			serviceCode = " " + e.ServiceCode
		}
		return fmt.Sprintf("s3 %s %q: HTTP %d%s (%s)", e.Operation, key, e.StatusCode, serviceCode, e.Kind)
	}
	return fmt.Sprintf("s3 %s %q: %s error", e.Operation, key, e.Kind)
}

// IsNotFound reports whether err is a provider-independent missing-object
// response.
func IsNotFound(err error) bool {
	var s3Err *S3Error
	return errors.As(err, &s3Err) && s3Err.Kind == S3ErrorNotFound
}

// IsTemporary reports whether retrying the operation may succeed. The stores
// already performs its configured bounded retries before returning an error.
func IsTemporary(err error) bool {
	var s3Err *S3Error
	return errors.As(err, &s3Err) && s3Err.Retryable
}

type cancelCloser struct {
	body   io.Closer
	cancel context.CancelFunc
}

func (c cancelCloser) Close() error {
	err := c.body.Close()
	c.cancel()
	return err
}

type s3RequestSettings struct {
	timeout        time.Duration
	attempts       int
	retryBaseDelay time.Duration
	retryJitter    func(minimum, maximum time.Duration) time.Duration
	maxObjectBytes int64
}

var defaultS3HTTPClient = &http.Client{Transport: &http.Transport{
	Proxy:                 http.ProxyFromEnvironment,
	DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          100,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ResponseHeaderTimeout: 30 * time.Second,
	ExpectContinueTimeout: time.Second,
}}

func readS3Error(reader io.Reader) (string, bool) {
	body, err := io.ReadAll(io.LimitReader(reader, maxS3ErrorBodyBytes+1))
	if err != nil {
		return "", false
	}
	truncated := int64(len(body)) > maxS3ErrorBodyBytes
	if truncated {
		body = body[:maxS3ErrorBodyBytes]
	}
	decoder := xml.NewDecoder(bytes.NewReader(body))
	for {
		token, err := decoder.Token()
		if err != nil {
			return "", truncated
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "Code" {
			continue
		}
		var code string
		if decoder.DecodeElement(&code, &start) != nil || !safeServiceCode(code) {
			return "", truncated
		}
		return code, truncated
	}
}

func safeServiceCode(code string) bool {
	if code == "" || len(code) > 64 {
		return false
	}
	for _, char := range code {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '.' || char == '_' || char == '-' {
			continue
		}
		return false
	}
	return true
}

func classifyS3Status(operation, key string, statusCode int, serviceCode string, truncated bool) *S3Error {
	kind := S3ErrorUnexpected
	retryable := false
	switch statusCode {
	case http.StatusBadRequest:
		kind = S3ErrorInvalidRequest
	case http.StatusUnauthorized:
		kind = S3ErrorAuthentication
	case http.StatusForbidden:
		kind = S3ErrorPermission
	case http.StatusNotFound, http.StatusGone:
		kind = S3ErrorNotFound
	case http.StatusConflict:
		kind = S3ErrorConflict
	case http.StatusRequestTimeout:
		kind, retryable = S3ErrorTimeout, true
	case http.StatusTooEarly, http.StatusTooManyRequests:
		kind, retryable = S3ErrorThrottled, true
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		kind, retryable = S3ErrorUnavailable, true
	}
	return &S3Error{Operation: operation, Key: key, Kind: kind, StatusCode: statusCode, ServiceCode: serviceCode, Retryable: retryable, BodyTruncated: truncated}
}

func retryDelay(base time.Duration, attempt int, retryAfter string, jitter func(minimum, maximum time.Duration) time.Duration) time.Duration {
	if seconds, err := strconv.ParseInt(strings.TrimSpace(retryAfter), 10, 64); err == nil && seconds >= 0 {
		if seconds >= int64(maxS3RetryDelay/time.Second) {
			return maxS3RetryDelay
		}
		return time.Duration(seconds) * time.Second
	}
	if at, err := http.ParseTime(retryAfter); err == nil {
		delay := time.Until(at)
		if delay < 0 {
			return 0
		}
		if delay > maxS3RetryDelay {
			return maxS3RetryDelay
		}
		return delay
	}
	delay := base
	if delay > maxS3RetryDelay {
		delay = maxS3RetryDelay
	}
	for i := 1; i < attempt && delay < maxS3RetryDelay; i++ {
		delay *= 2
		if delay > maxS3RetryDelay {
			delay = maxS3RetryDelay
		}
	}
	minimum := delay - delay/2
	if jitter == nil {
		jitter = defaultRetryJitter
	}
	selected := jitter(minimum, delay)
	if selected < minimum {
		return minimum
	}
	if selected > delay {
		return delay
	}
	return selected
}

func defaultRetryJitter(minimum, maximum time.Duration) time.Duration {
	if maximum <= minimum {
		return minimum
	}
	return minimum + time.Duration(mathrand.Int64N(int64(maximum-minimum)+1))
}

func waitForRetry(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func safeErrorKey(key string) string {
	key = strings.Map(func(char rune) rune {
		if char < 0x20 || char == 0x7f {
			return '\ufffd'
		}
		return char
	}, key)
	const maximum = 256
	if len(key) > maximum {
		return key[:maximum] + "..."
	}
	return key
}

// newRequestSettings applies the shared bounds and defaults of the artifact
// HTTP stores.
func newRequestSettings(requestTimeout time.Duration, maxAttempts int, retryBase time.Duration, retryJitter func(minimum, maximum time.Duration) time.Duration, maxObject int64) (s3RequestSettings, error) {
	timeout := requestTimeout
	if timeout == 0 {
		timeout = DefaultS3RequestTimeout
	}
	if timeout < 0 {
		return s3RequestSettings{}, errors.New("S3 request timeout must be positive")
	}
	attempts := maxAttempts
	if attempts == 0 {
		attempts = DefaultS3MaxAttempts
	}
	if attempts < 1 || attempts > maxS3Attempts {
		return s3RequestSettings{}, fmt.Errorf("S3 max attempts must be between 1 and %d", maxS3Attempts)
	}
	retryBaseDelay := retryBase
	if retryBaseDelay == 0 {
		retryBaseDelay = defaultRetryDelay
	}
	if retryBaseDelay < 0 {
		return s3RequestSettings{}, errors.New("S3 retry delay cannot be negative")
	}
	maxObjectBytes := maxObject
	if maxObjectBytes == 0 {
		maxObjectBytes = DefaultS3MaxObjectBytes
	}
	if maxObjectBytes < 1 {
		return s3RequestSettings{}, errors.New("S3 maximum object size must be positive")
	}
	return s3RequestSettings{
		timeout: timeout, attempts: attempts, retryBaseDelay: retryBaseDelay,
		retryJitter: retryJitter, maxObjectBytes: maxObjectBytes,
	}, nil
}
