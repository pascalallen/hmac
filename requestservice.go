package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
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

	r := &RequestService{public, bytes}

	return r, nil
}

func (rs *RequestService) SignRequest(request http.Request) (*http.Request, error) {
	method := strings.ToUpper(request.Method)
	authority := request.Host
	path := request.URL.Path
	query := request.URL.RawQuery
	timestamp := time.Now().Unix()
	content, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}

	headers, err := buildHeaders(timestamp, string(content))
	if err != nil {
		return nil, err
	}

	canonicalRequest := createCanonicalRequestString(method, authority, path, query, headers)

	headers["Authorization"] = "HMAC-SHA256"
	headers["Credential"] = rs.public
	headers["Signature"] = rs.createSignature(canonicalRequest, timestamp)

	// TODO: Sort headers?

	for name, value := range headers {
		request.Header.Set(name, value)
	}

	return &request, nil
}

func buildHeaders(timestamp int64, content string) (map[string]string, error) {
	headers := make(map[string]string)

	nonce, err := GenerateSecureRandom(8)
	if err != nil {
		return nil, err
	}

	headers["X-Timestamp"] = strconv.FormatInt(timestamp, 10)
	headers["X-Nonce"] = nonce

	if len(content) != 0 {
		contentHash := sha256.New()
		contentHash.Write([]byte(content))
		contentHashString := base64.StdEncoding.EncodeToString(contentHash.Sum(nil))
		headers["X-Content-SHA256"] = contentHashString
	}

	return headers, nil
}

// TODO: extract?
func createCanonicalRequestString(method string, authority string, path string, query string, headers map[string]string) string {
	if len(path) == 0 {
		path = "/"
	}

	headerString := ""
	for name, value := range headers {
		headerString += name + ":" + value + "\n"
	}

	if len(query) != 0 {
		query = "?" + query
	}

	return fmt.Sprintf("%s %s%s%s\n%s", method, authority, path, query, headerString)
}

// TODO: extract?
func (rs *RequestService) createSignature(canonicalRequest string, timestamp int64) string {
	requestHash := sha256.New()
	requestHash.Write([]byte(canonicalRequest))
	requestHashString := base64.StdEncoding.EncodeToString(requestHash.Sum(nil))

	stringToSign := fmt.Sprintf("HMAC-SHA256\n%d\n%s", timestamp, requestHashString)

	dateHash := hmac.New(sha256.New, rs.private)
	dateHash.Write([]byte(strconv.FormatInt(timestamp, 10)))

	signingHash := hmac.New(sha256.New, dateHash.Sum(nil))
	signingHash.Write([]byte("signed-request"))

	signature := hmac.New(sha256.New, signingHash.Sum(nil))
	signature.Write([]byte(stringToSign))

	return base64.StdEncoding.EncodeToString(signature.Sum(nil))
}
