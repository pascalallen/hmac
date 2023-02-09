package hmac

import (
	"crypto/rand"
	"strconv"
)

// GenerateSecureRandom generates a secure key to use with HMAC authentication.
// The returned string may be used as a public or private key.
func GenerateSecureRandom(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	i, err := strconv.ParseInt(string(bytes), 2, 0)
	if err != nil {
		return "", err
	}

	return strconv.FormatInt(i, 16), nil
}
