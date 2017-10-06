package mysql

import (
	"time"

	"github.com/kusubooru/monban/monban"
)

func (db *MonbanDB) createTables() error {
	if _, err := db.Exec(tableUsers); err != nil {
		return err
	}

	return nil
}

func (db *MonbanDB) insertAnonymous() error {
	_, err := db.GetUser("Anonymous")
	switch err {
	case monban.ErrNotFound:
		// Insert anonymous user.
		u := &monban.User{
			Name:  "Anonymous",
			Class: "anonymous",
			// Original joindate on old system.
			Joined: time.Date(2009, 7, 19, 5, 26, 16, 0, time.UTC),
		}
		if err := db.CreateUser(u); err != nil {
			return err
		}
	case nil:
	default:
		return err
	}
	return nil
}

func (db *MonbanDB) dropSchema() error {
	if _, err := db.Exec(`DROP TABLE users`); err != nil {
		return err
	}
	return nil
}

const (
	tableUsers = `
CREATE TABLE IF NOT EXISTS users (
	id BIGINT NOT NULL AUTO_INCREMENT UNIQUE,
	name VARCHAR(32) NOT NULL,
	pass BINARY(60) NOT NULL,
	email VARCHAR(254) NOT NULL DEFAULT '',
	class VARCHAR(32) NOT NULL DEFAULT 'user',
	admin BOOL NOT NULL DEFAULT FALSE,
	created DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	joined DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (id),
	UNIQUE KEY (name)
)`
)
