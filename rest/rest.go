package rest

import (
	"encoding/json"
	"log"
	"net/http"

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
			if err := json.NewEncoder(w).Encode(e); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
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
	s.handlers = gziphandler.GzipHandler(s.mux)
	s.mux.Handle("/api/v0/auth/login", handler(s.handleLogin))
	s.mux.Handle("/api/v0/auth/refresh", handler(s.handleRefresh))
	return s
}

// ServeHTTP satisfies the http.Handler interface for a server.
func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.TLS != nil {
		w.Header().Set("Strict-Transport-Security", "max-age=86400; includeSubDomains")
	}
	s.handlers.ServeHTTP(w, r)
}

// TODO: Should username and password be sent via headers?

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

func (s *server) handleRefresh(w http.ResponseWriter, r *http.Request) error {
	return E(nil, http.StatusText(http.StatusNotImplemented), http.StatusNotImplemented)
}
