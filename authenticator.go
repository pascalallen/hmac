package hmac

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

type Authenticator struct {
	public        string
	private       []byte
	timeTolerance int64
	ErrorCode     int
	ErrorMessage  string
}

var requiredHeaders = []string{
	"Authorization",
	"Credential",
	"Signature",
	"X-Timestamp",
	"X-Nonce",
}

func NewAuthenticator(public string, private string, timeTolerance int64) (*Authenticator, error) {
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

	return a, nil
}

func (a *Authenticator) Validate(r http.Request) bool {
	for _, h := range requiredHeaders {
		if r.Header.Get(h) == "" {
			a.ErrorCode = http.StatusUnprocessableEntity
			a.ErrorMessage = fmt.Sprintf("%s is a required header", h)

			return false
		}
	}

	requestTime := time.Now().Unix()
	timestamp, _ := strconv.ParseInt(r.Header.Get("X-Timestamp"), 10, 64)
	tolerance := a.timeTolerance
	if requestTime < timestamp || requestTime-tolerance > timestamp {
		a.ErrorCode = http.StatusBadRequest
		a.ErrorMessage = "Timestamp out of bounds"

		return false
	}

	if a.public != r.Header.Get("Credential") {
		a.ErrorCode = http.StatusForbidden
		a.ErrorMessage = "Not authorized"

		return false
	}

	var content []byte
	if _, err := r.Body.Read(content); err != nil {
		a.ErrorCode = http.StatusUnprocessableEntity
		a.ErrorMessage = "Error reading request body"

		return false
	}
	if len(content) > 0 && r.Header.Get("X-Content-SHA256") == "" {
		a.ErrorCode = http.StatusUnprocessableEntity
		a.ErrorMessage = "X-Content-SHA256 header is required with content"

		return false
	}
	if len(content) > 0 {
		contentHash := sha256.New()
		contentHash.Write(content)
		if bytes.Compare(contentHash.Sum(nil), []byte(r.Header.Get("X-Content-SHA256"))) != 0 {
			a.ErrorCode = http.StatusBadRequest
			a.ErrorMessage = "Invalid content hash"

			return false
		}
	}

	method := r.Method
	authority := r.Host
	path := r.URL.Path
	query := r.URL.RawQuery

	headers := make(map[string]string)
	headers["X-Timestamp"] = strconv.FormatInt(timestamp, 10)
	headers["X-Nonce"] = r.Header.Get("X-Nonce")
	if r.Header.Get("X-Content-SHA256") != "" {
		headers["X-Content-SHA256"] = r.Header.Get("X-Content-SHA256")
	}

	canonicalRequest := CreateCanonicalRequestString(method, authority, path, query, headers)

	signature := CreateSignature(canonicalRequest, timestamp, string(a.private))

	if bytes.Compare([]byte(signature), []byte(r.Header.Get("Signature"))) != 0 {
		a.ErrorCode = http.StatusForbidden
		a.ErrorMessage = "Not authorized"

		return false
	}

	return true
}
