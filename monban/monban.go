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
		Duration: time.Duration(15 * time.Minute),
		CSRF:     csrfToken,
	}
	signedAccessToken, err := jwt.Encode(accessToken, []byte(s.secret))
	if err != nil {
		return nil, fmt.Errorf("access token creation failed: %v", err)
	}

	// Create Refresh token.
	// TODO: Maybe use simple token?
	refreshTokenID := jwt.NewUUID()
	refreshToken := &jwt.Token{
		ID:       refreshTokenID,
		Subject:  userID,
		Duration: time.Duration(72 * time.Hour),
		CSRF:     csrfToken,
	}
	signedRefreshToken, err := jwt.Encode(refreshToken, []byte(s.secret))
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

func (s *authService) Refresh(refreshToken string) (*Token, error) {
	return nil, fmt.Errorf("not implemented")
}
