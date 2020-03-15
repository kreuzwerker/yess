// Package encrypt provides encryption and decryption for ephemeral keys.
package encrypt

import (
	nacl "golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/sha3"
)

// Decrypt decrypts a msg with secretbox, using SHA3-256 as key derivation function and a zero-nonce
func Decrypt(sk, shpe []byte) ([]byte, bool) {

	var (
		dk    = sha3.Sum256(sk)
		key   [32]byte
		nonce [24]byte
	)

	copy(key[:], dk[:])

	return nacl.Open(nil, shpe, &nonce, &key)

}

// Encrypt encrypts a msg with secretbox, using SHA3-256 as key derivation function and a zero-nonce
func Encrypt(sk, shp []byte) []byte {

	var (
		dk    = sha3.Sum256(sk)
		key   [32]byte
		nonce [24]byte // zero
	)

	copy(key[:], dk[:])

	return nacl.Seal(nil, shp, &nonce, &key)

}
