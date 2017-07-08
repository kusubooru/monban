package monban

import (
	"errors"
	"fmt"
	"time"

	"github.com/kusubooru/monban/jwt"
	"github.com/kusubooru/monban/jwt/csrf"
	"github.com/kusubooru/shimmie"
)

var (
	// ErrWrongCredentials is returned when credentials do not match.
	ErrWrongCredentials = errors.New("wrong username or password")
	// ErrInvalidToken is returned when a refresh token is invalid.
	ErrInvalidToken = errors.New("invalid token")
)

// Whitelist describes the operations needed to keep refresh tokens in a
// "whitelist" session storage. If a refresh token exists in the storage and
// assuming it is not expired then it is considered valid.
//
// Reap should run every second to clean up expired refresh tokens assuming the
// whitelist implementation (such as BoltDB) does not support auto expiration
// of values. Reap is meant to be called manually, once, on a separate
// goroutine at the start of the program.
type Whitelist interface {
	GetToken(tokenID string) (*jwt.Token, error)
	PutToken(tokenID string, t *jwt.Token) error
	Reap(time.Duration) error
	Close() error
}

// Grant is the result of successful authentication and contains access and
// refresh tokens.
type Grant struct {
	Access  string
	Refresh string
}

// AuthService specifies the operations needed for authentication.
type AuthService interface {
	Login(username, password string) (*Grant, error)
	Refresh(refreshToken string) (*Grant, error)
}

type authService struct {
	shimmie   shimmie.Store
	secret    string
	whitelist Whitelist
	accTokDur time.Duration
	refTokDur time.Duration
	issuer    string
}

// NewAuthService should be used for creating a new AuthService by providing a
// shimmie Store and a secret.
func NewAuthService(s shimmie.Store, wl Whitelist, accTokDur, refTokDur time.Duration, issuer, secret string) AuthService {
	return &authService{shimmie: s, secret: secret, whitelist: wl, accTokDur: accTokDur, refTokDur: refTokDur, issuer: issuer}
}

func (s *authService) Login(username, password string) (*Grant, error) {
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
	token, err := s.createTokens()
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (s *authService) Refresh(refreshToken string) (*Grant, error) {
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

	ok := s.verifyToken(tok)
	if !ok {
		return nil, ErrInvalidToken
	}

	// TODO: Check db

	token, err := s.createTokens()
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (s *authService) verifyToken(t *jwt.Token) bool {
	if t.Issuer != s.issuer {
		return false
	}
	if t.Duration != s.refTokDur {
		return false
	}
	return true
}

func (s *authService) createTokens() (*Grant, error) {
	// Create CSRF token.
	// TODO: Is CSRF token needed?
	csrfToken, err := csrf.NewToken()
	if err != nil {
		return nil, fmt.Errorf("CSRF token creation failed: %v", err)
	}

	// get current time
	now := time.Now()

	// Create Access token.
	// TODO: Specify claims.
	userID := jwt.NewUUID()
	accessToken := &jwt.Token{
		Subject:   userID,
		Issuer:    s.issuer,
		Duration:  s.accTokDur,
		CSRF:      csrfToken,
		ExpiresAt: now.Add(s.accTokDur).Unix(),
		IssuedAt:  now.Unix(),
	}
	signedAccessToken, err := jwt.Encode(accessToken, []byte(s.secret))
	if err != nil {
		return nil, fmt.Errorf("access token creation failed: %v", err)
	}

	// Create Refresh token.
	// TODO: Maybe use simple token?
	refreshTokenID := jwt.NewUUID()
	refreshToken := &jwt.Token{
		ID:        refreshTokenID,
		Subject:   userID,
		Issuer:    s.issuer,
		Duration:  s.refTokDur,
		CSRF:      csrfToken,
		ExpiresAt: now.Add(s.refTokDur).Unix(),
		IssuedAt:  now.Unix(),
	}
	signedRefreshToken, err := jwt.Encode(refreshToken, []byte(s.secret))
	if err != nil {
		return nil, fmt.Errorf("refresh token creation failed: %v", err)
	}

	// TODO: Store refreshTokenID or simple token on cache/redis/db.
	if err := s.whitelist.PutToken(refreshToken.ID, refreshToken); err != nil {
		return nil, err
	}

	grant := &Grant{
		Access:  signedAccessToken,
		Refresh: signedRefreshToken,
	}
	return grant, nil
}
