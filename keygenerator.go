package hmac

import (
	"crypto/rand"
	"encoding/hex"
)

func GenerateSecureRandom(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	hexKey := hex.EncodeToString(bytes)

	return hexKey, nil
}
