package monban

import (
	"errors"
	"fmt"
	"time"

	"github.com/kusubooru/monban/jwt"
	"github.com/kusubooru/monban/jwt/csrf"
	"github.com/kusubooru/shimmie"
)

const (
	defaultMonbanIssuer         = "monban"
	defaultAccessTokenDuration  = 15 * time.Minute
	defaultRefreshTokenDuration = 72 * time.Hour
)

var (
	// ErrWrongCredentials is returned when credentials do not match.
	ErrWrongCredentials = errors.New("wrong username or password")
	// ErrInvalidToken is returned when a refresh token is invalid.
	ErrInvalidToken = errors.New("invalid token")
)

// Token is the result of successful authentication and contains access and
// refresh tokens.
type Token struct {
	Access  string
	Refresh string
}

// AuthService specifies the operations needed for authentication.
type AuthService interface {
	Login(username, password string) (*Token, error)
	Refresh(refreshToken string) (*Token, error)
}

type authService struct {
	shimmie shimmie.Store
	secret  string
}

// NewAuthService should be used for creating a new AuthService by providing a
// shimmie Store and a secret.
func NewAuthService(s shimmie.Store, secret string) AuthService {
	return &authService{shimmie: s, secret: secret}
}

func (s *authService) Login(username, password string) (*Token, error) {
	if username == "" || password == "" {
		return nil, ErrWrongCredentials
	}

	// Verify User.
	_, err := s.shimmie.Verify(username, password)
	if err != nil {
		if err != shimmie.ErrNotFound && err != shimmie.ErrWrongCredentials {
			return nil, ErrWrongCredentials
		}
		return nil, fmt.Errorf("verify failed: %v", err)
	}
	token, err := createTokens(defaultMonbanIssuer, defaultAccessTokenDuration, defaultRefreshTokenDuration, s.secret)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (s *authService) Refresh(refreshToken string) (*Token, error) {
	if refreshToken == "" {
		return nil, ErrInvalidToken
	}

	tok, valid, err := jwt.Decode(refreshToken, []byte(s.secret))
	if err != nil {
		if err == jwt.ErrInvalidToken {
			return nil, ErrInvalidToken
		}
		return nil, err
	}
	if !valid {
		return nil, ErrInvalidToken
	}

	ok := verifyToken(tok)
	if !ok {
		return nil, ErrInvalidToken
	}

	// TODO: Check db

	token, err := createTokens(defaultMonbanIssuer, defaultAccessTokenDuration, defaultRefreshTokenDuration, s.secret)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func verifyToken(t *jwt.Token) bool {
	if t.Issuer != defaultMonbanIssuer {
		return false
	}
	if t.Duration != defaultRefreshTokenDuration {
		return false
	}
	return true
}

func createTokens(issuer string, accessTokenDuration, refreshTokenDuration time.Duration, secret string) (*Token, error) {
	// Create CSRF token.
	// TODO: Is CSRF token needed?
	csrfToken, err := csrf.NewToken()
	if err != nil {
		return nil, fmt.Errorf("CSRF token creation failed: %v", err)
	}

	// Create Access token.
	// TODO: Specify claims.
	userID := jwt.NewUUID()
	accessToken := &jwt.Token{
		Subject:  userID,
		Issuer:   issuer,
		Duration: accessTokenDuration,
		CSRF:     csrfToken,
	}
	signedAccessToken, err := jwt.Encode(accessToken, []byte(secret))
	if err != nil {
		return nil, fmt.Errorf("access token creation failed: %v", err)
	}

	// Create Refresh token.
	// TODO: Maybe use simple token?
	refreshTokenID := jwt.NewUUID()
	refreshToken := &jwt.Token{
		ID:       refreshTokenID,
		Subject:  userID,
		Issuer:   issuer,
		Duration: refreshTokenDuration,
		CSRF:     csrfToken,
	}
	signedRefreshToken, err := jwt.Encode(refreshToken, []byte(secret))
	if err != nil {
		return nil, fmt.Errorf("refresh token creation failed: %v", err)
	}

	// TODO: Store refreshTokenID or simple token on cache/redis/db.

	token := &Token{
		Access:  signedAccessToken,
		Refresh: signedRefreshToken,
	}
	return token, nil
}
