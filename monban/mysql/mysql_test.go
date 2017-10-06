// +build db

package mysql

import (
	"flag"
	"fmt"
	"testing"

	_ "github.com/go-sql-driver/mysql"
)

var (
	user   = flag.String("user", "monban", "username to use to run tests on MySQL")
	pass   = flag.String("pass", "", "password to use to run tests on MySQL")
	host   = flag.String("host", "localhost", "host for connecting to MySQL and run the tests")
	port   = flag.String("port", "3306", "port for connecting to MySQL and run the tests")
	dbname = flag.String("dbname", "monban_test", "test database to use to run the tests")
)

func init() {
	flag.Parse()
}

func setup(t *testing.T) *MonbanDB {
	if *pass == "" {
		t.Errorf("No password provided for user %q to connect to MySQL and run the tests.", *user)
		t.Errorf("These tests need a MySQL account %q that has access to test database %q.", *user, *dbname)
		t.Fatal("Use: go test -tags=db -pass '<db password>'")
	}
	datasource := fmt.Sprintf("%s:%s@(%s:%s)/%s?parseTime=true", *user, *pass, *host, *port, *dbname)
	db, err := OpenMonbanDB(datasource)
	if err != nil {
		t.Fatalf("OpenMonbanDB failed for datasource %q: %v", datasource, err)
	}
	return db
}

func teardown(t *testing.T, db *MonbanDB) {
	if err := db.dropSchema(); err != nil {
		t.Error(err)
	}
	if err := db.Close(); err != nil {
		t.Error(err)
	}
}
