// Package share implements shamir secret sharing with a SHA3-256 hash appended to the original secret to identify a successful reconstruction
package share

import (
	"bytes"
	"fmt"

	"github.com/hashicorp/vault/shamir"
	"golang.org/x/crypto/sha3"
)

var Debug func(string, ...interface{})

const errInvalidHash = "invalid hash, parts are missing"

// Combine attempts to combine the given parts
func Combine(shps [][]byte) ([]byte, error) {

	if Debug != nil {
		Debug("combining %d parts", len(shps))

		for idx, shp := range shps {
			Debug("share %d: %x", idx+1, shp)
		}

	}

	data, err := shamir.Combine(shps)

	if err != nil {
		return nil, err
	}

	var (
		p  = data[0 : len(data)-32]
		sh = data[len(data)-32:]
	)

	if Debug != nil {
		Debug("data %x, hash %x", p, sh)
	}

	if !bytes.Equal(hash(p), sh) {
		return nil, fmt.Errorf(errInvalidHash)
	}

	return p, nil

}

// Split splits the given secret into parts
func Split(s []byte, parts, threshold int) ([][]byte, error) {

	if Debug != nil {
		Debug("splitting s %x into %d parts with a threshold of %d", s, parts, threshold)
	}

	sh := append(s, hash(s)...)

	shps, err := shamir.Split(sh, parts, threshold)

	if err != nil {
		return nil, err
	}

	if Debug != nil {

		for idx, shp := range shps {
			Debug("shp %d: %x", idx+1, shp)
		}

	}

	return shps, nil

}

func hash(s []byte) []byte {

	out := sha3.Sum256(s)

	return out[:]

}
