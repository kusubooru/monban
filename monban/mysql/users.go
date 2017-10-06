package mysql

import (
	"database/sql"
	"fmt"

	"github.com/kusubooru/monban/monban"
	"golang.org/x/crypto/bcrypt"
)

func (db *MonbanDB) CreateUser(u *monban.User) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(u.Pass), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("error calculating password hash: %v", err)
	}
	_, err = db.insertUser.Exec(
		u.Name,
		hash,
		u.Email,
		u.Class,
		u.Admin,
	)
	if err != nil {
		return err
	}
	return nil
}

func (db *MonbanDB) GetUser(name string) (*monban.User, error) {
	u := &monban.User{}
	err := db.selectUser.QueryRow(name).Scan(
		&u.ID,
		&u.Name,
		&u.Pass,
		&u.Email,
		&u.Class,
		&u.Admin,
		&u.Created,
	)
	if err == sql.ErrNoRows {
		return nil, monban.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

const (
	insertUserStmt = `
	INSERT users
    SET
      name=?,
      pass=?,
      email=?,
      class=?,
      admin=?
	`
	selectUserStmt = `
	SELECT
	  id,
	  name,
	  pass,
	  email,
	  class,
	  admin,
	  created
	FROM users
	WHERE name = ?
	`
)
