// +build db

package mysql

import (
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/kusubooru/monban/monban"
)

func TestCreateUser(t *testing.T) {
	db := setup(t)
	defer teardown(t, db)

	u := &monban.User{Name: "foo", Pass: "bar"}
	if err := db.CreateUser(u); err != nil {
		t.Fatal("CreateUser failed:", err)
	}

	have, err := db.GetUser("foo")
	if err != nil {
		t.Fatal("GetUser failed:", err)
	}
	// id
	if got, want := have.ID, int64(1); got != want {
		t.Errorf("GetUser ID = %d, want %d", got, want)
	}
	// name
	if got, want := have.Name, "foo"; got != want {
		t.Errorf("GetUser Name = %s, want %s", got, want)
	}
	// pass
	if err := bcrypt.CompareHashAndPassword([]byte(have.Pass), []byte(u.Pass)); err != nil {
		t.Errorf("GetUser Pass wrong bcrypt hash: %v", err)
	}
}
