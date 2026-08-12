package hmac

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"
)

func signedTestRequest(t *testing.T, publicKey string, privateKey string) *http.Request {
	t.Helper()

	request, err := http.NewRequest(
		http.MethodPost,
		"http://localhost:8080?abc=xyz",
		bytes.NewReader([]byte(`{"foo": "bar"}`)),
	)
	if err != nil {
		t.Fatal(err)
	}

	requestService, err := NewRequestService(publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	signedRequest, err := requestService.SignRequest(request)
	if err != nil {
		t.Fatal(err)
	}

	return signedRequest
}

func assertValidationError(t *testing.T, err error, message string) {
	t.Helper()

	var validationError *ValidationError
	if !errors.As(err, &validationError) {
		t.Fatalf("expected *ValidationError, got %v", err)
	}
	if validationError.Message != message {
		t.Fatalf("expected error message %q, got %q", message, validationError.Message)
	}
}

func TestThatNewAuthenticatorReturnsInstanceOfAuthenticator(t *testing.T) {
	publicKey := GenerateSecureRandom(16)
	privateKey := GenerateSecureRandom(16)

	authenticator, err := NewAuthenticator(publicKey, privateKey, 300)

	if authenticator == nil || err != nil {
		t.Fatal(err)
	}
}

func TestThatNewAuthenticatorReturnsErrorEmptyPublicKey(t *testing.T) {
	errMsg := "public key required"
	publicKey := ""
	privateKey := GenerateSecureRandom(16)

	authenticator, err := NewAuthenticator(publicKey, privateKey, 300)

	if authenticator != nil || err.Error() != errMsg {
		t.Fatal(err)
	}
}

func TestThatNewAuthenticatorReturnsErrorEmptyPrivateKey(t *testing.T) {
	errMsg := "private key required"
	publicKey := GenerateSecureRandom(16)
	privateKey := ""

	authenticator, err := NewAuthenticator(publicKey, privateKey, 300)

	if authenticator != nil || err.Error() != errMsg {
		t.Fatal(err)
	}
}

func TestThatNewAuthenticatorReturnsErrorMalformedPrivateKey(t *testing.T) {
	errMsg := "malformed private key"
	publicKey := GenerateSecureRandom(16)
	privateKey := "true"

	authenticator, err := NewAuthenticator(publicKey, privateKey, 300)

	if authenticator != nil || err.Error() != errMsg {
		t.Fatal(err)
	}
}

func TestThatValidateReturnsTrueValidRequest(t *testing.T) {
	publicKey := GenerateSecureRandom(16)
	privateKey := GenerateSecureRandom(16)

	signedRequest := signedTestRequest(t, publicKey, privateKey)

	authenticator, _ := NewAuthenticator(publicKey, privateKey, 300)
	isValid, err := authenticator.Validate(signedRequest)

	if !isValid || err != nil {
		t.Fatal(err)
	}
}

func TestThatValidatePreservesRequestBody(t *testing.T) {
	publicKey := GenerateSecureRandom(16)
	privateKey := GenerateSecureRandom(16)
	content := `{"foo": "bar"}`

	signedRequest := signedTestRequest(t, publicKey, privateKey)

	authenticator, _ := NewAuthenticator(publicKey, privateKey, 300)
	isValid, err := authenticator.Validate(signedRequest)
	if !isValid {
		t.Fatal(err)
	}

	body, err := io.ReadAll(signedRequest.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != content {
		t.Fatalf("expected body %q after Validate, got %q", content, string(body))
	}
}

func TestThatValidateReturnsTrueRequestWithoutBody(t *testing.T) {
	publicKey := GenerateSecureRandom(16)
	privateKey := GenerateSecureRandom(16)

	request, _ := http.NewRequest(http.MethodGet, "http://localhost:8080", nil)

	requestService, _ := NewRequestService(publicKey, privateKey)
	signedRequest, err := requestService.SignRequest(request)
	if err != nil {
		t.Fatal(err)
	}

	authenticator, _ := NewAuthenticator(publicKey, privateKey, 300)
	isValid, err := authenticator.Validate(signedRequest)

	if !isValid || err != nil {
		t.Fatal(err)
	}
}

func TestThatValidateReturnsFalseMissingHeader(t *testing.T) {
	errMsg := "Authorization is a required header"
	publicKey := GenerateSecureRandom(16)
	privateKey := GenerateSecureRandom(16)

	signedRequest := signedTestRequest(t, publicKey, privateKey)
	signedRequest.Header.Del("Authorization")

	authenticator, _ := NewAuthenticator(publicKey, privateKey, 300)
	isValid, err := authenticator.Validate(signedRequest)

	if isValid {
		t.Fatal("expected validation to fail")
	}
	assertValidationError(t, err, errMsg)
}

func TestThatValidateReturnsFalseInvalidTimestamp(t *testing.T) {
	errMsg := "Invalid timestamp"
	publicKey := GenerateSecureRandom(16)
	privateKey := GenerateSecureRandom(16)

	signedRequest := signedTestRequest(t, publicKey, privateKey)
	signedRequest.Header.Set("X-Timestamp", "some invalid timestamp")

	authenticator, _ := NewAuthenticator(publicKey, privateKey, 300)
	isValid, err := authenticator.Validate(signedRequest)

	if isValid {
		t.Fatal("expected validation to fail")
	}
	assertValidationError(t, err, errMsg)
}

func TestThatValidateReturnsFalseTimeOutOfBounds(t *testing.T) {
	errMsg := "Timestamp out of bounds"
	publicKey := GenerateSecureRandom(16)
	privateKey := GenerateSecureRandom(16)

	signedRequest := signedTestRequest(t, publicKey, privateKey)
	signedRequest.Header.Set("X-Timestamp", strconv.FormatInt(time.Now().Add(time.Hour*1).Unix(), 10))

	authenticator, _ := NewAuthenticator(publicKey, privateKey, 300)
	isValid, err := authenticator.Validate(signedRequest)

	if isValid {
		t.Fatal("expected validation to fail")
	}
	assertValidationError(t, err, errMsg)
}

func TestThatValidateAllowsFutureTimestampWithinTolerance(t *testing.T) {
	publicKey := GenerateSecureRandom(16)
	privateKey := GenerateSecureRandom(16)

	timestamp := time.Now().Add(time.Second * 100).Unix()
	request, _ := http.NewRequest(http.MethodGet, "http://localhost:8080", nil)

	headers := BuildHeaders(timestamp, nil)
	canonicalRequest := CreateCanonicalRequestString(request.Method, request.Host, request.URL.Path, request.URL.RawQuery, headers)

	decodedPrivateKey, _ := hex.DecodeString(privateKey)
	headers["Authorization"] = "HMAC-SHA256"
	headers["Credential"] = publicKey
	headers["Signature"] = CreateSignature(canonicalRequest, timestamp, string(decodedPrivateKey))
	for name, value := range headers {
		request.Header.Set(name, value)
	}

	authenticator, _ := NewAuthenticator(publicKey, privateKey, 300)
	isValid, err := authenticator.Validate(request)

	if !isValid || err != nil {
		t.Fatal(err)
	}
}

func TestThatValidateReturnsFalseInvalidCredential(t *testing.T) {
	errMsg := "Not authorized"
	publicKey := GenerateSecureRandom(16)
	privateKey := GenerateSecureRandom(16)

	signedRequest := signedTestRequest(t, publicKey, privateKey)
	signedRequest.Header.Set("Credential", "invalid-credential-header")

	authenticator, _ := NewAuthenticator(publicKey, privateKey, 300)
	isValid, err := authenticator.Validate(signedRequest)

	if isValid {
		t.Fatal("expected validation to fail")
	}
	assertValidationError(t, err, errMsg)
}

func TestThatValidateReturnsFalseMissingContentHeader(t *testing.T) {
	errMsg := "X-Content-SHA256 header is required with content"
	publicKey := GenerateSecureRandom(16)
	privateKey := GenerateSecureRandom(16)

	signedRequest := signedTestRequest(t, publicKey, privateKey)
	signedRequest.Header.Del("X-Content-SHA256")

	authenticator, _ := NewAuthenticator(publicKey, privateKey, 300)
	isValid, err := authenticator.Validate(signedRequest)

	if isValid {
		t.Fatal("expected validation to fail")
	}
	assertValidationError(t, err, errMsg)
}

func TestThatValidateReturnsFalseInvalidContentHash(t *testing.T) {
	errMsg := "Invalid content hash"
	publicKey := GenerateSecureRandom(16)
	privateKey := GenerateSecureRandom(16)

	signedRequest := signedTestRequest(t, publicKey, privateKey)
	signedRequest.Header.Set("X-Content-SHA256", "invalid content hash")

	authenticator, _ := NewAuthenticator(publicKey, privateKey, 300)
	isValid, err := authenticator.Validate(signedRequest)

	if isValid {
		t.Fatal("expected validation to fail")
	}
	assertValidationError(t, err, errMsg)
}

func TestThatValidateReturnsFalseInvalidSignature(t *testing.T) {
	errMsg := "Not authorized"
	publicKey := GenerateSecureRandom(16)
	privateKey := GenerateSecureRandom(16)

	signedRequest := signedTestRequest(t, publicKey, privateKey)
	signedRequest.Header.Set("Signature", "invalid signature")

	authenticator, _ := NewAuthenticator(publicKey, privateKey, 300)
	isValid, err := authenticator.Validate(signedRequest)

	if isValid {
		t.Fatal("expected validation to fail")
	}
	assertValidationError(t, err, errMsg)
}

type memoryNonceStore struct {
	seen map[string]bool
}

func (s *memoryNonceStore) Seen(nonce string) bool {
	return s.seen[nonce]
}

func (s *memoryNonceStore) Store(nonce string) {
	s.seen[nonce] = true
}

func TestThatValidateRejectsReplayedNonce(t *testing.T) {
	errMsg := "Nonce already used"
	publicKey := GenerateSecureRandom(16)
	privateKey := GenerateSecureRandom(16)

	signedRequest := signedTestRequest(t, publicKey, privateKey)

	store := &memoryNonceStore{seen: make(map[string]bool)}
	authenticator, _ := NewAuthenticator(publicKey, privateKey, 300, WithNonceStore(store))

	isValid, err := authenticator.Validate(signedRequest)
	if !isValid {
		t.Fatal(err)
	}

	isValid, err = authenticator.Validate(signedRequest)
	if isValid {
		t.Fatal("expected replayed request to fail validation")
	}
	assertValidationError(t, err, errMsg)
}

func TestThatValidateDoesNotStoreNonceOfInvalidRequest(t *testing.T) {
	publicKey := GenerateSecureRandom(16)
	privateKey := GenerateSecureRandom(16)

	signedRequest := signedTestRequest(t, publicKey, privateKey)
	nonce := signedRequest.Header.Get("X-Nonce")

	forgedRequest := signedTestRequest(t, publicKey, privateKey)
	forgedRequest.Header.Set("X-Nonce", nonce)
	forgedRequest.Header.Set("Signature", "invalid signature")

	store := &memoryNonceStore{seen: make(map[string]bool)}
	authenticator, _ := NewAuthenticator(publicKey, privateKey, 300, WithNonceStore(store))

	if isValid, _ := authenticator.Validate(forgedRequest); isValid {
		t.Fatal("expected forged request to fail validation")
	}

	isValid, err := authenticator.Validate(signedRequest)
	if !isValid {
		t.Fatalf("valid request rejected after forged attempt: %v", err)
	}
}
