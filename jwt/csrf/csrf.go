package csrf

import (
	"crypto/rand"
	"encoding/base64"
)

// csrfTokenSize is the size of the CSRF token in bytes. Usually 32 bytes (256
// bits) is more than sufficient and common in a large web frameworks like
// Django and Rails.
const csrfTokenSize = 32

// generateRandomBytes returns securely generated random bytes. It will return
// an error if the system's secure random number generator fails to function
// correctly.
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if len(b) == n.
	if err != nil {
		return nil, err
	}

	return b, nil
}

// generateRandomString returns a URL-safe, base64 encoded securely generated
// random string. It will return an error if the system's secure random number
// generator fails to function correctly.
func generateRandomString(s int) (string, error) {
	b, err := generateRandomBytes(s)
	return base64.URLEncoding.EncodeToString(b), err
}

// NewToken returns a new random CSRF token.
func NewToken() (string, error) {
	return generateRandomString(csrfTokenSize)
}
