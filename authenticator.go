package hmac

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// ValidationError describes why a request failed validation. Code is a
// suggested HTTP status code for the response.
type ValidationError struct {
	Code    int
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}

// NonceStore tracks nonces of successfully validated requests so that a
// captured request cannot be replayed within the timestamp tolerance window.
// Implementations may expire entries older than the tolerance window.
type NonceStore interface {
	Seen(nonce string) bool
	Store(nonce string)
}

type Authenticator struct {
	public        string
	private       []byte
	timeTolerance int64
	nonceStore    NonceStore
}

type AuthenticatorOption func(*Authenticator)

// WithNonceStore enables replay protection. Without a store, a captured
// request remains valid for the full timestamp tolerance window.
func WithNonceStore(store NonceStore) AuthenticatorOption {
	return func(a *Authenticator) {
		a.nonceStore = store
	}
}

var requiredHeaders = []string{
	"Authorization",
	"Credential",
	"Signature",
	"X-Timestamp",
	"X-Nonce",
}

func NewAuthenticator(public string, private string, timeTolerance int64, options ...AuthenticatorOption) (*Authenticator, error) {
	if len(public) == 0 {
		return nil, fmt.Errorf("public key required")
	}

	if len(private) == 0 {
		return nil, fmt.Errorf("private key required")
	}

	b, err := hex.DecodeString(private)
	if err != nil {
		return nil, fmt.Errorf("malformed private key")
	}

	a := &Authenticator{
		public:        public,
		private:       b,
		timeTolerance: timeTolerance,
	}

	for _, option := range options {
		option(a)
	}

	return a, nil
}

// Validate reports whether the request carries a valid signature. When
// validation fails, the returned error is a *ValidationError. The request
// body is restored so callers can still read it after validation.
func (a *Authenticator) Validate(r *http.Request) (bool, error) {
	for _, h := range requiredHeaders {
		if r.Header.Get(h) == "" {
			return false, &ValidationError{
				Code:    http.StatusUnprocessableEntity,
				Message: fmt.Sprintf("%s is a required header", h),
			}
		}
	}

	timestamp, err := strconv.ParseInt(r.Header.Get("X-Timestamp"), 10, 64)
	if err != nil {
		return false, &ValidationError{
			Code:    http.StatusBadRequest,
			Message: "Invalid timestamp",
		}
	}

	requestTime := time.Now().Unix()
	if timestamp < requestTime-a.timeTolerance || timestamp > requestTime+a.timeTolerance {
		return false, &ValidationError{
			Code:    http.StatusBadRequest,
			Message: "Timestamp out of bounds",
		}
	}

	if a.public != r.Header.Get("Credential") {
		return false, &ValidationError{
			Code:    http.StatusForbidden,
			Message: "Not authorized",
		}
	}

	var content []byte
	if r.Body != nil {
		content, err = io.ReadAll(r.Body)
		if err != nil {
			return false, &ValidationError{
				Code:    http.StatusBadRequest,
				Message: "Unable to read request body",
			}
		}
		r.Body = io.NopCloser(bytes.NewReader(content))
	}

	if len(content) > 0 && r.Header.Get("X-Content-SHA256") == "" {
		return false, &ValidationError{
			Code:    http.StatusUnprocessableEntity,
			Message: "X-Content-SHA256 header is required with content",
		}
	}
	if len(content) > 0 {
		contentHash := sha256.Sum256(content)
		expected := base64.StdEncoding.EncodeToString(contentHash[:])
		if !hmac.Equal([]byte(expected), []byte(r.Header.Get("X-Content-SHA256"))) {
			return false, &ValidationError{
				Code:    http.StatusBadRequest,
				Message: "Invalid content hash",
			}
		}
	}

	headers := make(map[string]string)
	headers["X-Timestamp"] = strconv.FormatInt(timestamp, 10)
	headers["X-Nonce"] = r.Header.Get("X-Nonce")
	if r.Header.Get("X-Content-SHA256") != "" {
		headers["X-Content-SHA256"] = r.Header.Get("X-Content-SHA256")
	}

	canonicalRequest := CreateCanonicalRequestString(r.Method, r.Host, r.URL.Path, r.URL.RawQuery, headers)

	signature := CreateSignature(canonicalRequest, timestamp, string(a.private))

	if !hmac.Equal([]byte(signature), []byte(r.Header.Get("Signature"))) {
		return false, &ValidationError{
			Code:    http.StatusForbidden,
			Message: "Not authorized",
		}
	}

	if a.nonceStore != nil {
		nonce := r.Header.Get("X-Nonce")
		if a.nonceStore.Seen(nonce) {
			return false, &ValidationError{
				Code:    http.StatusForbidden,
				Message: "Nonce already used",
			}
		}
		a.nonceStore.Store(nonce)
	}

	return true, nil
}
