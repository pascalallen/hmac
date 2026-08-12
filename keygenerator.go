package hmac

import (
	"crypto/rand"
	"encoding/hex"
)

// GenerateSecureRandom generates a secure key to use with HMAC authentication.
// The returned string may be used as a public or private key. It panics if
// the system source of secure randomness fails, since silently returning a
// weak key would be worse.
func GenerateSecureRandom(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		panic("hmac: unable to read from secure random source: " + err.Error())
	}

	return hex.EncodeToString(bytes)
}
