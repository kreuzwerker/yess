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
func Combine(parts [][]byte) ([]byte, error) {

	if Debug != nil {
		Debug("combining %d parts", len(parts))

		for idx, share := range parts {
			Debug("share %d: %x", idx+1, share)
		}

	}

	data, err := shamir.Combine(parts)

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
func Split(secret []byte, parts, threshold int) ([][]byte, error) {

	if Debug != nil {
		Debug("splitting %x into %d parts with a threshold of %d", secret, parts, threshold)
	}

	data := append(secret, hash(secret)...)
	shares, err := shamir.Split(data, parts, threshold)

	if err != nil {
		return nil, err
	}

	if Debug != nil {

		for idx, share := range shares {
			Debug("share %d: %x", idx+1, share)
		}

	}

	return shares, nil

}

func hash(data []byte) []byte {

	out := sha3.Sum256(data)

	return out[:]

}
