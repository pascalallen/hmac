package hmac

import (
	"bytes"
	"net/http"
	"strconv"
	"testing"
	"time"
)

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

	request, _ := http.NewRequest(
		http.MethodPost,
		"http://localhost:8080?abc=xyz",
		bytes.NewReader([]byte(`{"foo": "bar"}`)),
	)

	requestService, _ := NewRequestService(publicKey, privateKey)
	signedRequest := requestService.SignRequest(request)

	authenticator, _ := NewAuthenticator(publicKey, privateKey, 300)
	isValid := authenticator.Validate(*signedRequest)

	if isValid == false {
		t.Fatal(authenticator.ErrorMessage)
	}
}

func TestThatValidateReturnsFalseMissingHeader(t *testing.T) {
	errMsg := "Authorization is a required header"
	publicKey := GenerateSecureRandom(16)
	privateKey := GenerateSecureRandom(16)

	request, _ := http.NewRequest(
		http.MethodPost,
		"http://localhost:8080",
		bytes.NewReader([]byte(`{"foo": "bar"}`)),
	)

	requestService, _ := NewRequestService(publicKey, privateKey)
	signedRequest := requestService.SignRequest(request)
	signedRequest.Header.Del("Authorization")

	authenticator, _ := NewAuthenticator(publicKey, privateKey, 300)
	isValid := authenticator.Validate(*signedRequest)

	if isValid == true || authenticator.ErrorMessage != errMsg {
		t.Fatal(authenticator.ErrorMessage)
	}
}

func TestThatValidateReturnsFalseInvalidTimestamp(t *testing.T) {
	errMsg := "Invalid timestamp"
	publicKey := GenerateSecureRandom(16)
	privateKey := GenerateSecureRandom(16)

	request, _ := http.NewRequest(
		http.MethodPost,
		"http://localhost:8080",
		bytes.NewReader([]byte(`{"foo": "bar"}`)),
	)

	requestService, _ := NewRequestService(publicKey, privateKey)
	signedRequest := requestService.SignRequest(request)
	signedRequest.Header.Set("X-Timestamp", "some invalid timestamp")

	authenticator, _ := NewAuthenticator(publicKey, privateKey, 300)
	isValid := authenticator.Validate(*signedRequest)

	if isValid == true || authenticator.ErrorMessage != errMsg {
		t.Fatal(authenticator.ErrorMessage)
	}
}

func TestThatValidateReturnsFalseTimeOutOfBounds(t *testing.T) {
	errMsg := "Timestamp out of bounds"
	publicKey := GenerateSecureRandom(16)
	privateKey := GenerateSecureRandom(16)

	request, _ := http.NewRequest(
		http.MethodPost,
		"http://localhost:8080",
		bytes.NewReader([]byte(`{"foo": "bar"}`)),
	)

	requestService, _ := NewRequestService(publicKey, privateKey)
	signedRequest := requestService.SignRequest(request)
	signedRequest.Header.Set("X-Timestamp", strconv.FormatInt(time.Now().Add(time.Hour*1).Unix(), 10))

	authenticator, _ := NewAuthenticator(publicKey, privateKey, 300)
	isValid := authenticator.Validate(*signedRequest)

	if isValid == true || authenticator.ErrorMessage != errMsg {
		t.Fatal(authenticator.ErrorMessage)
	}
}

func TestThatValidateReturnsFalseInvalidCredential(t *testing.T) {
	errMsg := "Not authorized"
	publicKey := GenerateSecureRandom(16)
	privateKey := GenerateSecureRandom(16)

	request, _ := http.NewRequest(
		http.MethodPost,
		"http://localhost:8080",
		bytes.NewReader([]byte(`{"foo": "bar"}`)),
	)

	requestService, _ := NewRequestService(publicKey, privateKey)
	signedRequest := requestService.SignRequest(request)
	signedRequest.Header.Set("Credential", "invalid-credential-header")

	authenticator, _ := NewAuthenticator(publicKey, privateKey, 300)
	isValid := authenticator.Validate(*signedRequest)

	if isValid == true || authenticator.ErrorMessage != errMsg {
		t.Fatal(authenticator.ErrorMessage)
	}
}

func TestThatValidateReturnsFalseMissingContentHeader(t *testing.T) {
	errMsg := "X-Content-SHA256 header is required with content"
	publicKey := GenerateSecureRandom(16)
	privateKey := GenerateSecureRandom(16)

	request, _ := http.NewRequest(
		http.MethodPost,
		"http://localhost:8080",
		bytes.NewReader([]byte(`{"foo": "bar"}`)),
	)

	requestService, _ := NewRequestService(publicKey, privateKey)
	signedRequest := requestService.SignRequest(request)
	signedRequest.Header.Del("X-Content-SHA256")

	authenticator, _ := NewAuthenticator(publicKey, privateKey, 300)
	isValid := authenticator.Validate(*signedRequest)

	if isValid == true || authenticator.ErrorMessage != errMsg {
		t.Fatal(authenticator.ErrorMessage)
	}
}

func TestThatValidateReturnsFalseInvalidContentHash(t *testing.T) {
	errMsg := "Invalid content hash"
	publicKey := GenerateSecureRandom(16)
	privateKey := GenerateSecureRandom(16)

	request, _ := http.NewRequest(
		http.MethodPost,
		"http://localhost:8080",
		bytes.NewReader([]byte(`{"foo": "bar"}`)),
	)

	requestService, _ := NewRequestService(publicKey, privateKey)
	signedRequest := requestService.SignRequest(request)
	signedRequest.Header.Set("X-Content-SHA256", "invalid content hash")

	authenticator, _ := NewAuthenticator(publicKey, privateKey, 300)
	isValid := authenticator.Validate(*signedRequest)

	if isValid == true || authenticator.ErrorMessage != errMsg {
		t.Fatal(authenticator.ErrorMessage)
	}
}

func TestThatValidateReturnsFalseInvalidSignature(t *testing.T) {
	errMsg := "Not authorized"
	publicKey := GenerateSecureRandom(16)
	privateKey := GenerateSecureRandom(16)

	request, _ := http.NewRequest(
		http.MethodPost,
		"http://localhost:8080",
		bytes.NewReader([]byte(`{"foo": "bar"}`)),
	)

	requestService, _ := NewRequestService(publicKey, privateKey)
	signedRequest := requestService.SignRequest(request)
	signedRequest.Header.Set("Signature", "invalid signature")

	authenticator, _ := NewAuthenticator(publicKey, privateKey, 300)
	isValid := authenticator.Validate(*signedRequest)

	if isValid == true || authenticator.ErrorMessage != errMsg {
		t.Fatal(authenticator.ErrorMessage)
	}
}
