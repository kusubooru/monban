package mysql

import (
	"database/sql"
	"fmt"
	"time"
)

type MonbanDB struct {
	*sql.DB
	// prepared statements
	insertUser *sql.Stmt
	selectUser *sql.Stmt
}

// OpenMonbanDB opens a new database connection with the specified driver and
// connection string.
func OpenMonbanDB(dataSource string) (*MonbanDB, error) {
	db, err := sql.Open("mysql", dataSource)
	if err != nil {
		return nil, fmt.Errorf("error connecting to mysql: %v", err)
	}
	// per issue https://github.com/go-sql-driver/mysql/issues/257
	db.SetMaxIdleConns(0)
	if err := pingDatabase(db); err != nil {
		return nil, fmt.Errorf("mysql ping attempts failed: %v", err)
	}
	d := &MonbanDB{DB: db}
	if err := d.createTables(); err != nil {
		return nil, fmt.Errorf("error creating tables: %v", err)
	}
	if err := d.prepareStatements(); err != nil {
		return nil, fmt.Errorf("error preparing statements: %v", err)
	}
	if err := d.insertAnonymous(); err != nil {
		return nil, fmt.Errorf("error inserting anonymous user: %v", err)
	}
	return d, nil
}

func (db *MonbanDB) prepareStatements() error {
	var err error
	db.insertUser, err = db.Prepare(insertUserStmt)
	if err != nil {
		return err
	}
	db.selectUser, err = db.Prepare(selectUserStmt)
	if err != nil {
		return err
	}
	return nil
}

// pingDatabase is a helper function to ping the database with backoff to
// ensure a connection can be established before we proceed.
func pingDatabase(db *sql.DB) (err error) {
	for i := 0; i < 10; i++ {
		err = db.Ping()
		if err == nil {
			return
		}
		// database ping failed. retry in 1s
		time.Sleep(time.Second)
	}
	return
}

func (db *MonbanDB) Close() error {
	for _, stmt := range []*sql.Stmt{db.insertUser, db.selectUser} {
		if err := stmt.Close(); err != nil {
			return err
		}
	}
	return db.DB.Close()
}
