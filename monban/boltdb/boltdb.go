package boltdb

import (
	"log"
	"time"

	"github.com/boltdb/bolt"
	"github.com/kusubooru/monban/monban"
)

const (
	whitelistBucket = "whitelist"
)

type whitelist struct {
	*bolt.DB
}

func (db *whitelist) Close() error {
	return db.DB.Close()
}

// openBolt creates and opens a bolt database at the given path. If the file does
// not exist then it will be created automatically. After opening it creates
// all the needed buckets.
func openBolt(file string) *bolt.DB {
	db, err := bolt.Open(file, 0600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		log.Fatalln("bolt open failed:", err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		_, err = tx.CreateBucketIfNotExists([]byte(whitelistBucket))
		return err
	})
	if err != nil {
		log.Fatalln("bolt bucket creation failed:", err)
	}
	return db
}

// NewWhitelist opens the bolt database file and returns an implementation for
// monban.Whitelist. The bolt database file will be created if it does not
// exist.
func NewWhitelist(boltFile string) monban.Whitelist {
	db := openBolt(boltFile)
	return &whitelist{db}
}
