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

// SignRequest signs the request in place and returns it. The request body,
// if any, is restored so it can still be read after signing.
func (rs *RequestService) SignRequest(request *http.Request) (*http.Request, error) {
	timestamp := time.Now().Unix()

	var content []byte
	if request.Body != nil {
		var err error
		content, err = io.ReadAll(request.Body)
		if err != nil {
			return nil, fmt.Errorf("unable to read request body: %w", err)
		}
		request.Body = io.NopCloser(bytes.NewReader(content))
	}

	headers := BuildHeaders(timestamp, content)

	canonicalRequest := CreateCanonicalRequestString(request.Method, request.Host, request.URL.Path, request.URL.RawQuery, headers)

	headers["Authorization"] = "HMAC-SHA256"
	headers["Credential"] = rs.public
	headers["Signature"] = CreateSignature(canonicalRequest, timestamp, string(rs.private))

	for name, value := range headers {
		request.Header.Set(name, value)
	}

	return request, nil
}
