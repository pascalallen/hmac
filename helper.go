package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
)

func CreateCanonicalRequestString(method string, authority string, path string, query string, headers map[string]string) string {
	if len(path) == 0 {
		path = "/"
	}

	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	headerString := ""
	for _, k := range keys {
		headerString += k + ":" + headers[k] + "\n"
	}

	if len(query) != 0 {
		query = "?" + query
	}

	return fmt.Sprintf("%s %s%s%s\n%s", method, authority, path, query, headerString)
}

func CreateSignature(canonicalRequest string, timestamp int64, private string) string {
	requestHash := sha256.New()
	requestHash.Write([]byte(canonicalRequest))
	requestHashString := base64.StdEncoding.EncodeToString(requestHash.Sum(nil))

	stringToSign := fmt.Sprintf("HMAC-SHA256\n%d\n%s", timestamp, requestHashString)

	dateHash := hmac.New(sha256.New, []byte("HMAC"+private))
	dateHash.Write([]byte(strconv.FormatInt(timestamp, 10)))

	signingHash := hmac.New(sha256.New, dateHash.Sum(nil))
	signingHash.Write([]byte("signed-request"))

	signature := hmac.New(sha256.New, signingHash.Sum(nil))
	signature.Write([]byte(stringToSign))

	return base64.StdEncoding.EncodeToString(signature.Sum(nil))
}

func BuildHeaders(timestamp int64, content []byte) map[string]string {
	headers := make(map[string]string)
	nonce := GenerateSecureRandom(8)

	headers["X-Timestamp"] = strconv.FormatInt(timestamp, 10)
	headers["X-Nonce"] = nonce

	if len(content) > 0 {
		contentHash := sha256.New()
		contentHash.Write(content)
		contentHashString := base64.StdEncoding.EncodeToString(contentHash.Sum(nil))
		headers["X-Content-SHA256"] = contentHashString
	}

	return headers
}
