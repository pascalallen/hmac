package hmac

import (
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
