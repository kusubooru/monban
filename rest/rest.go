package rest

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/NYTimes/gziphandler"
	"github.com/kusubooru/monban/monban"
)

type handler func(http.ResponseWriter, *http.Request) error

func (fn handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := fn(w, r); err != nil {
		switch e := err.(type) {
		case *Error:
			w.Header().Set("Content-Type", "application/json; charset=UTF-8")
			w.WriteHeader(e.Code)
			if isInternal(err) {
				log.Println(err)
			}
			if encErr := json.NewEncoder(w).Encode(e); encErr != nil {
				http.Error(w, encErr.Error(), http.StatusInternalServerError)
			}
		default:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

type server struct {
	handlers http.Handler // stack of wrapped http.Handlers
	mux      *http.ServeMux
	auth     monban.AuthService
}

// NewServer initializes and returns a new HTTP server.
func NewServer(auth monban.AuthService) http.Handler {
	s := &server{mux: http.NewServeMux(), auth: auth}
	s.handlers = gziphandler.GzipHandler(allowCORS(s.mux))
	s.mux.Handle("/api/v0/auth/login", handler(s.handleLogin))
	s.mux.Handle("/api/v0/auth/refresh", handler(s.handleRefresh))
	return s
}

// allowCORS allows Cross Origin Resource Sharing from any origin.
// Don't do this without consideration in production systems.
func allowCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			if r.Method == "OPTIONS" && r.Header.Get("Access-Control-Request-Method") != "" {
				preflightHandler(w, r)
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}

func preflightHandler(w http.ResponseWriter, r *http.Request) {
	headers := []string{"Content-Type", "Accept"}
	w.Header().Set("Access-Control-Allow-Headers", strings.Join(headers, ","))
	methods := []string{"GET", "HEAD", "POST", "PUT", "DELETE"}
	w.Header().Set("Access-Control-Allow-Methods", strings.Join(methods, ","))
	return
}

// ServeHTTP satisfies the http.Handler interface for a server.
func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.TLS != nil {
		w.Header().Set("Strict-Transport-Security", "max-age=86400; includeSubDomains")
	}
	s.handlers.ServeHTTP(w, r)
}

// TODO(jin): Should username and password be sent via headers?

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResp struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) error {
	if r.Method != "POST" {
		return E(nil, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
	req := new(loginReq)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		return E(err, "expecting user credentials", http.StatusBadRequest)
	}
	tok, err := s.auth.Login(req.Username, req.Password)
	if err != nil {
		if err == monban.ErrWrongCredentials {
			return E(err, "wrong username or password", http.StatusUnauthorized)
		}
		return E(err, "login failed", http.StatusInternalServerError)
	}
	resp := &loginResp{AccessToken: tok.Access, RefreshToken: tok.Refresh}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		return E(err, "login response encode failed", http.StatusInternalServerError)
	}
	return nil
}

type refreshReq struct {
	RefreshToken string `json:"refresh_token"`
}

type refreshResp struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (s *server) handleRefresh(w http.ResponseWriter, r *http.Request) error {
	if r.Method != "POST" {
		return E(nil, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
	req := new(refreshReq)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		return E(err, "expecting refresh token", http.StatusBadRequest)
	}
	if req.RefreshToken == "" {
		return E(nil, "expecting refresh_token in request", http.StatusBadRequest)
	}

	tok, err := s.auth.Refresh(req.RefreshToken)
	if err != nil {
		if err == monban.ErrInvalidToken {
			return E(err, "invalid token", http.StatusUnauthorized)
		}
		return E(err, "refresh failed", http.StatusInternalServerError)
	}
	resp := &refreshResp{AccessToken: tok.Access, RefreshToken: tok.Refresh}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		return E(err, "refresh response encode failed", http.StatusInternalServerError)
	}
	return nil
}
