package hmac

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"
)

type RequestService struct {
	public  string
	private []byte
}

func NewRequestService(public string, private string) (*RequestService, error) {
	if len(public) == 0 {
		return nil, fmt.Errorf("public key required")
	}

	if len(private) == 0 {
		return nil, fmt.Errorf("private key required")
	}

	decodedPrivateKey, err := hex.DecodeString(private)
	if err != nil {
		return nil, fmt.Errorf("invalid private key")
	}

	return &RequestService{public, decodedPrivateKey}, nil
}

func (rs *RequestService) SignRequest(request *http.Request) *http.Request {
	method := request.Method
	authority := request.Host
	path := request.URL.Path
	query := request.URL.RawQuery
	timestamp := time.Now().Unix()

	content, _ := io.ReadAll(request.Body)
	request.Body = io.NopCloser(bytes.NewReader(content))

	headers := BuildHeaders(timestamp, content)

	canonicalRequest := CreateCanonicalRequestString(method, authority, path, query, headers)

	headers["Authorization"] = "HMAC-SHA256"
	headers["Credential"] = rs.public
	headers["Signature"] = CreateSignature(canonicalRequest, timestamp, string(rs.private))

	for name, value := range headers {
		request.Header.Set(name, value)
	}

	return request
}
