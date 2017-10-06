package mysql

func (db *MonbanDB) createTables() error {
	if _, err := db.Exec(tableUsers); err != nil {
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
	created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (id),
	UNIQUE KEY (name)
)`
)
