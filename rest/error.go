package rest

import (
	"fmt"
	"net/http"
)

type internal interface {
	Internal() bool
}

// isInternal returns true if err is internal.
func isInternal(err error) bool {
	e, ok := err.(internal)
	return ok && e.Internal()
}

// Error is the HTTP error returned from the Monban API.
type Error struct {
	err     error  `json:"-"`
	Message string `json:"message"`
	Code    int    `json:"code"`
}

// Internal implements the Internal interface and allows to inspect if the
// error is internal.
func (e *Error) Internal() bool { return e.Code == http.StatusInternalServerError }
func (e *Error) Error() string  { return fmt.Sprintf("%d %v: %v", e.Code, e.Message, e.err) }

// E constructs an Error and should be used as a shorthand.
func E(err error, message string, code int) error {
	return &Error{err: err, Message: message, Code: code}
}
