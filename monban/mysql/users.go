package mysql

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/kusubooru/monban/monban"
	"golang.org/x/crypto/bcrypt"
)

func (db *MonbanDB) CreateUser(u *monban.User) error {
	var err error
	hash := []byte("")
	if u.Pass != "" {
		hash, err = bcrypt.GenerateFromPassword([]byte(u.Pass), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("error calculating password hash: %v", err)
		}
	}

	// Migrating user's original join date from the old system.
	if !u.Joined.Equal(time.Time{}) {
		insert := insertUserStmt + ", joined = ?"
		_, err = db.Exec(insert,
			u.Name,
			hash,
			u.Email,
			u.Class,
			u.Admin,
			u.Joined,
		)
		if err != nil {
			return err
		}
		return nil
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
		&u.Joined,
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
	  created,
	  joined
	FROM users
	WHERE name = ?
	`
)
