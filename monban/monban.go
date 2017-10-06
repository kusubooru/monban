package monban

import (
	"errors"
	"fmt"
	"reflect"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/kusubooru/monban/jwt"
	"github.com/kusubooru/monban/jwt/csrf"
	"github.com/kusubooru/shimmie"
)

var (
	// ErrWrongCredentials is returned when credentials do not match.
	ErrWrongCredentials = errors.New("wrong username or password")
	// ErrInvalidToken is returned when a refresh token is invalid.
	ErrInvalidToken = errors.New("invalid token")
	// ErrNotFound is returned whenever an item does not exist in the database.
	ErrNotFound = errors.New("item not found")
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

type User struct {
	ID      int64
	Name    string
	Pass    string
	Email   string
	Class   string
	Admin   bool
	Created time.Time
	Joined  time.Time
}

// UserStore specifies the operations needed for storing and retrieving Monban
// users.
type UserStore interface {
	CreateUser(u *User) error
	GetUser(name string) (*User, error)
}

type authService struct {
	users     UserStore
	shimmie   shimmie.Store
	secret    string
	whitelist Whitelist
	accTokDur time.Duration
	refTokDur time.Duration
	issuer    string
}

// NewAuthService should be used for creating a new AuthService by providing a
// shimmie Store and a secret.
func NewAuthService(
	userStore UserStore,
	shimmieDB shimmie.Store,
	wl Whitelist,
	accTokDur time.Duration,
	refTokDur time.Duration,
	issuer string,
	secret string,
) AuthService {
	s := &authService{
		users:     userStore,
		shimmie:   shimmieDB,
		secret:    secret,
		whitelist: wl,
		accTokDur: accTokDur,
		refTokDur: refTokDur,
		issuer:    issuer,
	}
	return s
}

func (s *authService) Login(username, password string) (*Grant, error) {
	if username == "" || password == "" {
		return nil, ErrWrongCredentials
	}

	u, err := s.users.GetUser(username)
	switch err {
	case ErrNotFound:
		// Verify User from shimmie.
		_, err := s.shimmie.Verify(username, password)
		if err == shimmie.ErrNotFound || err == shimmie.ErrWrongCredentials {
			return nil, ErrWrongCredentials
		}
		if err != nil {
			return nil, fmt.Errorf("verify failed: %v", err)
		}
		// Credentials are correct. Migrate user.
		if err := s.migrateUser(username, password); err != nil {
			return nil, fmt.Errorf("user migration failed: %v", err)
		}
		u, err = s.users.GetUser(username)
		if err != nil {
			return nil, fmt.Errorf("error getting migrated user: %v", err)
		}
	case nil:
	default:
		return nil, fmt.Errorf("get user: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.Pass), []byte(password)); err != nil {
		return nil, ErrWrongCredentials
	}

	token, err := s.createTokens()
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (s *authService) migrateUser(username, password string) error {
	old, err := s.shimmie.GetUserByName(username)
	if err == shimmie.ErrNotFound {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	u := &User{
		Name:  username,
		Pass:  password,
		Email: old.Email,
		Class: old.Class,
	}
	if old.JoinDate != nil {
		u.Joined = *old.JoinDate
	}
	if old.Admin == "Y" {
		u.Admin = true
	}
	if s.users.CreateUser(u); err != nil {
		return err
	}
	return nil
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

	// Check that token exists in whitelist.
	wltok, err := s.whitelist.GetToken(tok.ID)
	if err != nil {
		return nil, err
	}

	ok := s.verifyToken(tok, wltok)
	if !ok {
		return nil, ErrInvalidToken
	}

	token, err := s.createTokens()
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (s *authService) verifyToken(t, storedToken *jwt.Token) bool {
	if t.Issuer != s.issuer {
		return false
	}
	if t.Duration != s.refTokDur {
		return false
	}
	if reflect.DeepEqual(t, storedToken) {
		return true
	}
	return false
}

func (s *authService) createTokens() (*Grant, error) {
	// Create CSRF token.
	// TODO(jin): Is CSRF token needed?
	csrfToken, err := csrf.NewToken()
	if err != nil {
		return nil, fmt.Errorf("CSRF token creation failed: %v", err)
	}

	// get current time
	now := time.Now()

	// Create Access token.
	// TODO(jin): Specify claims.
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
	// TODO(jin): Maybe use simple token?
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

	// TODO(jin): Store refreshTokenID or simple token on cache/redis/db.
	if err := s.whitelist.PutToken(refreshToken.ID, refreshToken); err != nil {
		return nil, err
	}

	grant := &Grant{
		Access:  signedAccessToken,
		Refresh: signedRefreshToken,
	}
	return grant, nil
}
