package jwt

import (
	"errors"
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	uuid "github.com/satori/go.uuid"
)

// Token is a JSON Web Token.
type Token struct {
	ID        string
	Issuer    string
	Subject   string
	Audience  string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Duration  time.Duration
	CSRF      string
}

type myCustomClaims struct {
	CSRF string `json:"csrf,omitempty"`
	jwt.StandardClaims
}

// Encode encodes and signs a JWT token.
func Encode(t *Token, secret []byte) (string, error) {
	claims := myCustomClaims{
		CSRF: t.CSRF,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: t.ExpiresAt.Unix(),
			IssuedAt:  t.IssuedAt.Unix(),
			Issuer:    t.Issuer,
			Subject:   t.Subject,
			Id:        t.ID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("sign token failed: %v", err)
	}
	return ss, nil
}

var (
	// ErrInvalidToken returned by Decode when the token is invalid.
	ErrInvalidToken = errors.New("invalid token")
)

// Decode parses a token from a string format and returns a Token struct.
func Decode(t string, secret []byte) (*Token, bool, error) {
	parsedToken, err := jwt.ParseWithClaims(t, &myCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Make sure token's signature wasn't changed.
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected siging method")
		}
		return secret, nil
	})
	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorMalformed != 0 {
				return nil, false, ErrInvalidToken
			} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
				// Token is either expired or not active yet.
				return nil, false, ErrInvalidToken
			} else {
				return nil, false, fmt.Errorf("could not handle this token: %v", err)
			}
		}
		return nil, false, fmt.Errorf("failed to decode claims: %v", err)
	}
	claims, ok := parsedToken.Claims.(*myCustomClaims)
	if !ok {
		return nil, parsedToken.Valid, fmt.Errorf("failed to decode custom claims")
	}
	sc := claims.StandardClaims
	issuedAt := time.Unix(sc.IssuedAt, 0)
	expiredAt := time.Unix(sc.ExpiresAt, 0)
	duration := expiredAt.Sub(issuedAt)

	token := &Token{
		CSRF:     claims.CSRF,
		ID:       sc.Id,
		Issuer:   sc.Issuer,
		Subject:  sc.Subject,
		Duration: duration,
	}
	return token, parsedToken.Valid, nil
}

// NewUUID provides a new UUID.
func NewUUID() string {
	return uuid.NewV4().String()
}
