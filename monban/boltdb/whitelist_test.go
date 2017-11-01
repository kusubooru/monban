package boltdb

import (
	"io/ioutil"
	"log"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/kusubooru/monban/jwt"
	"github.com/kusubooru/monban/monban"
)

func setup() (monban.Whitelist, *os.File) {
	f, err := ioutil.TempFile("", "monban_boltdb_tmpfile_")
	if err != nil {
		log.Fatal("could not create boltdb temp file for tests:", err)
	}
	return NewWhitelist(f.Name()), f
}

func teardown(whitelist monban.Whitelist, tmpfile *os.File) {
	//whitelist.Close()
	if err := os.Remove(tmpfile.Name()); err != nil {
		log.Println("could not remove boltdb temp file:", err)
	}
}

func TestWhitelist(t *testing.T) {
	whitelist, f := setup()
	defer teardown(whitelist, f)

	tokenID := "123"
	now := time.Now().Unix()
	tok := &jwt.Token{
		ID:       tokenID,
		IssuedAt: now,
	}

	err := whitelist.PutToken(tokenID, tok)
	if err != nil {
		t.Fatal("whitelist.PutToken:", err)
	}
	out, err := whitelist.GetToken(tokenID)
	if err != nil {
		t.Fatal("whitelist.GetToken failed:", err)
	}

	got := out
	want := &jwt.Token{ID: tokenID, IssuedAt: now}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("whitelist.GetToken(%q, %#v) lead to \n%#v, want \n%#v", tokenID, tok, got, want)
	}
}
