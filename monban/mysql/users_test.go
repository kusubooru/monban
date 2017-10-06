// +build db

package mysql

import (
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/kusubooru/monban/monban"
)

func TestMonbanDB_CreateUser(t *testing.T) {
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
	// id (1 should be the anonymous user)
	if got, want := have.ID, int64(2); got != want {
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

func TestMonbanDB_CreateUser_withJoined(t *testing.T) {
	db := setup(t)
	defer teardown(t, db)

	joined := time.Date(2009, 7, 19, 5, 26, 16, 0, time.UTC)
	u := &monban.User{Name: "foo", Pass: "bar", Joined: joined}
	if err := db.CreateUser(u); err != nil {
		t.Fatal("CreateUser failed:", err)
	}

	have, err := db.GetUser("foo")
	if err != nil {
		t.Fatal("GetUser failed:", err)
	}
	// joined
	if got, want := have.Joined, joined; !got.Equal(want) {
		t.Errorf("GetUser Joined = %v, want %v", got, want)
	}
}

func TestMonbanDB_GetUser_notFound(t *testing.T) {
	db := setup(t)
	defer teardown(t, db)

	_, got := db.GetUser("foo")
	if want := monban.ErrNotFound; got != want {
		t.Fatalf("GetUser for non existing user expected %q, got %q:", got, want)
	}
}
