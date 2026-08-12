package hmac

import (
	"bytes"
	"io"
	"net/http"
	"testing"
)

func TestThatNewRequestServiceReturnsInstanceOfRequestService(t *testing.T) {
	publicKey := GenerateSecureRandom(16)
	privateKey := GenerateSecureRandom(16)

	requestService, err := NewRequestService(publicKey, privateKey)

	if requestService == nil || err != nil {
		t.Fatal(err)
	}
}

func TestThatNewRequestServiceReturnsErrorMissingPublicKey(t *testing.T) {
	errMsg := "public key required"
	publicKey := ""
	privateKey := GenerateSecureRandom(16)

	requestService, err := NewRequestService(publicKey, privateKey)

	if requestService != nil || err.Error() != errMsg {
		t.Fatal(err)
	}
}

func TestThatNewRequestServiceReturnsErrorMissingPrivateKey(t *testing.T) {
	errMsg := "private key required"
	publicKey := GenerateSecureRandom(16)
	privateKey := ""

	requestService, err := NewRequestService(publicKey, privateKey)

	if requestService != nil || err.Error() != errMsg {
		t.Fatal(err)
	}
}

func TestThatNewRequestServiceReturnsErrorInvalidPrivateKey(t *testing.T) {
	errMsg := "invalid private key"
	publicKey := GenerateSecureRandom(16)
	privateKey := "0"

	requestService, err := NewRequestService(publicKey, privateKey)

	if requestService != nil || err.Error() != errMsg {
		t.Fatal(err)
	}
}

func TestThatSignRequestSignsRequestWithNilBody(t *testing.T) {
	publicKey := GenerateSecureRandom(16)
	privateKey := GenerateSecureRandom(16)

	request, _ := http.NewRequest(http.MethodGet, "http://localhost:8080", nil)

	requestService, _ := NewRequestService(publicKey, privateKey)
	signedRequest, err := requestService.SignRequest(request)

	if err != nil {
		t.Fatal(err)
	}
	if signedRequest.Header.Get("Signature") == "" {
		t.Fatal("expected Signature header to be set")
	}
	if signedRequest.Header.Get("X-Content-SHA256") != "" {
		t.Fatal("expected no X-Content-SHA256 header for bodyless request")
	}
}

func TestThatSignRequestPreservesRequestBody(t *testing.T) {
	publicKey := GenerateSecureRandom(16)
	privateKey := GenerateSecureRandom(16)
	content := `{"foo": "bar"}`

	request, _ := http.NewRequest(
		http.MethodPost,
		"http://localhost:8080",
		bytes.NewReader([]byte(content)),
	)

	requestService, _ := NewRequestService(publicKey, privateKey)
	signedRequest, err := requestService.SignRequest(request)
	if err != nil {
		t.Fatal(err)
	}

	body, err := io.ReadAll(signedRequest.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != content {
		t.Fatalf("expected body %q after SignRequest, got %q", content, string(body))
	}
}
