package hmac

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
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

	bytes, err := hex.DecodeString(private)
	if err != nil {
		return nil, err
	}

	return &RequestService{public, bytes}, nil
}

func (rs *RequestService) SignRequest(request *http.Request) (*http.Request, error) {
	method := request.Method
	authority := request.Host
	path := request.URL.Path
	query := request.URL.RawQuery
	timestamp := time.Now().Unix()

	var content []byte
	if _, err := request.Body.Read(content); err != nil {
		return nil, err
	}

	headers, err := rs.buildHeaders(timestamp, content)
	if err != nil {
		return nil, err
	}

	canonicalRequest := CreateCanonicalRequestString(method, authority, path, query, headers)

	headers["Signature"] = CreateSignature(canonicalRequest, timestamp, string(rs.private))

	// TODO: Sort headers?

	for name, value := range headers {
		request.Header.Set(name, value)
	}

	return request, nil
}

func (rs *RequestService) buildHeaders(timestamp int64, content []byte) (map[string]string, error) {
	headers := make(map[string]string)

	nonce, err := GenerateSecureRandom(8)
	if err != nil {
		return nil, err
	}

	headers["X-Timestamp"] = strconv.FormatInt(timestamp, 10)
	headers["X-Nonce"] = nonce

	if len(content) != 0 {
		contentHash := sha256.New()
		contentHash.Write(content)
		contentHashString := base64.StdEncoding.EncodeToString(contentHash.Sum(nil))
		headers["X-Content-SHA256"] = contentHashString
	}

	headers["Authorization"] = "HMAC-SHA256"
	headers["Credential"] = rs.public

	return headers, nil
}
