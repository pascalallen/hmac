package hmac

import (
	"crypto/rand"
	"encoding/hex"
)

// GenerateSecureRandom generates a secure key to use with HMAC authentication.
// The returned string may be used as a public or private key.
func GenerateSecureRandom(length int) string {
	bytes := make([]byte, length)
	_, _ = rand.Read(bytes)

	return hex.EncodeToString(bytes)
}
