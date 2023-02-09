package hmac

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestThatNewAuthenticatorReturnsInstanceOfAuthenticator(t *testing.T) {
	pub, _ := GenerateSecureRandom(16)
	priv, _ := GenerateSecureRandom(16)
	tim := time.Now().Add(time.Hour * 1).Unix()

	a, err := NewAuthenticator(pub, priv, tim)
	if a == nil || err != nil {
		t.Fatal(err)
	}
}

func TestThatNewAuthenticatorReturnsErrorEmptyPublicKey(t *testing.T) {
	errMsg := "public key required"
	pub := ""
	priv, _ := GenerateSecureRandom(16)
	tim := time.Now().Add(time.Hour * 1).Unix()

	a, err := NewAuthenticator(pub, priv, tim)
	if a != nil || err.Error() != errMsg {
		t.Fatal(err)
	}
}

func TestThatNewAuthenticatorReturnsErrorEmptyPrivateKey(t *testing.T) {
	errMsg := "private key required"
	pub, _ := GenerateSecureRandom(16)
	priv := ""
	tim := time.Now().Add(time.Hour * 1).Unix()

	a, err := NewAuthenticator(pub, priv, tim)
	if a != nil || err.Error() != errMsg {
		t.Fatal(err)
	}
}

func TestThatNewAuthenticatorReturnsErrorMalformedPrivateKey(t *testing.T) {
	errMsg := "malformed private key"
	pub, _ := GenerateSecureRandom(16)
	priv := "true"
	tim := time.Now().Add(time.Hour * 1).Unix()

	a, err := NewAuthenticator(pub, priv, tim)
	if a != nil || err.Error() != errMsg {
		t.Fatal(err)
	}
}

func TestThatValidateReturnsTrueOnValidRequest(t *testing.T) {
	pub, _ := GenerateSecureRandom(16)
	priv, _ := GenerateSecureRandom(16)
	requestService, _ := NewRequestService(pub, priv)

	jsonBytes, _ := json.Marshal(map[string]string{"foo": "bar"})
	request, _ := http.NewRequest("POST", "http://localhost:8080", bytes.NewReader(jsonBytes))
	r, _ := requestService.SignRequest(request)

	a, _ := NewAuthenticator(pub, priv, time.Now().Unix())
	v := a.Validate(*r)

	if v == false {
		t.Fatal(a.ErrorMessage)
	}
}
