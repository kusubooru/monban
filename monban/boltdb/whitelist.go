package boltdb

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"time"

	"github.com/boltdb/bolt"
	"github.com/kusubooru/monban/jwt"
)

func (db *whitelist) GetToken(tokenID string) (*jwt.Token, error) {
	tok := new(jwt.Token)
	buf := bytes.Buffer{}
	err := db.View(func(tx *bolt.Tx) error {
		value := tx.Bucket([]byte(whitelistBucket)).Get([]byte(tokenID))
		// Discard the first 8 bytes because that's where we store the time the
		// token was issued.
		value = value[8:]

		if _, werr := buf.Write(value); werr != nil {
			return fmt.Errorf("could not write 'GetToken value' to buffer: %v", werr)
		}

		if err := gob.NewDecoder(&buf).Decode(tok); err != nil {
			return fmt.Errorf("could not decode token %v", err)
		}
		return nil
	})
	return tok, err
}

func (db *whitelist) PutToken(tokenID string, tok *jwt.Token) error {
	err := db.Update(func(tx *bolt.Tx) error {
		buf := bytes.Buffer{}

		// Write the time the token was issued at as the first 8 bytes of the
		// value. This is useful to easier find out which tokens are expired
		// and delete them.
		time := tok.IssuedAt
		if time < 0 {
			return fmt.Errorf("token has negative time")
		}
		buf.Write(itob(time))

		// get bucket
		b := tx.Bucket([]byte(whitelistBucket))

		if err := gob.NewEncoder(&buf).Encode(tok); err != nil {
			return fmt.Errorf("could not encode new PutToken value: %v", err)
		}

		if err := b.Put([]byte(tokenID), buf.Bytes()); err != nil {
			return fmt.Errorf("could not put value: %v", err)
		}
		return nil
	})
	return err
}

// itob returns an 8-byte big endian representation of v.
func itob(v int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(v))
	return b
}

// Reap removes sessions older than a given duration.
// This function assumes that all session data is stored in a "sessions" bucket
// and the data is organized so the key is the session id and the value is
// laid out as:
//
//   -8 bytes-   --n bytes--
//   timestamp + sessiondata
//
// As written by Ben Johnson:
// https://gist.github.com/benbjohnson/a3e9e35f73dae8d15c49
func (db whitelist) Reap(duration time.Duration) error {
	// The batch size represents how many sessions we'll check at
	// a time for a given transaction. We don't want to check all the
	// sessions every time because that would lock the database for
	// too long if the sessions bucket gets too large.
	batchsz := 1000

	var seek []byte
	var prev []byte
	for {
		// Get the current timestamp.
		now := time.Now()

		// Iterate over a subset of keys at a time and delete old ones.
		err := db.Update(func(tx *bolt.Tx) error {
			c := tx.Bucket([]byte(whitelistBucket)).Cursor()

			var i int
			for k, v := c.Seek(prev); ; k, v = c.Next() {
				// If we hit the end of our sessions then exit and start over next time.
				if k == nil {
					seek = nil
					return nil
				}

				// If we have iterated over our batch size then save our place
				// and we'll start from there next time. We need to copy over
				// the bytes in "k" because it's not guarenteed to exist there
				// after the transaction is over.
				if i == batchsz {
					seek = make([]byte, len(k))
					copy(seek, k)
					return nil
				}

				// If we've made it this far then we can check if a session's
				// timestamp is older than our expiration "duration". If so
				// then we can delete the item in-place in the cursor.
				timestamp := time.Unix(int64(binary.BigEndian.Uint64(v)), 0)
				if now.Sub(timestamp) > duration {
					if err := c.Delete(); err != nil {
						return fmt.Errorf("delete: %s", err)
					}
				}
			}
		})
		if err != nil {
			return err
		}

		time.Sleep(1 * time.Second)
	}
}
