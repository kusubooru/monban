package jwt_test

import (
	"testing"
	"time"

	"github.com/kusubooru/monban/jwt"
)

func TestEncode(t *testing.T) {
	tests := []struct {
		token  *jwt.Token
		secret []byte
	}{
		{&jwt.Token{Subject: "1", Issuer: "issuer", Duration: time.Duration(5 * time.Second)}, []byte("secret")},
		{&jwt.Token{Subject: "", Issuer: "", Duration: 0}, []byte("")},
	}
	for _, tt := range tests {
		_, err := jwt.Encode(tt.token, tt.secret)
		if err != nil {
			t.Errorf("jwt.Encode(%q, %q) returned err: %v", tt.token, tt.secret, err)
		}
	}
}
