package hmac

import (
	"crypto/rand"
	"encoding/hex"
)

// GenerateSecureRandom generates a secure key to use with HMAC authentication.
// The returned string may be used as a public or private key.
func GenerateSecureRandom(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}
