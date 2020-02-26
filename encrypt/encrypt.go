// Package encrypt provides encryption and decryption for ephemeral keys.
package encrypt

import (
	nacl "golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/sha3"
)

// Decrypt decrypts a msg with secretbox, using SHA3-256 as key derivation function and a zero-nonce
func Decrypt(sharedKey, msg []byte) ([]byte, bool) {

	var (
		dk    = sha3.Sum256(sharedKey)
		nonce [24]byte
		key   [32]byte
	)

	copy(key[:], dk[:])

	return nacl.Open(nil, msg, &nonce, &key)

}

// Encrypt encrypts a msg with secretbox, using SHA3-256 as key derivation function and a zero-nonce
func Encrypt(sharedKey, msg []byte) []byte {

	var (
		dk    = sha3.Sum256(sharedKey)
		nonce [24]byte
		key   [32]byte
	)

	copy(key[:], dk[:])

	return nacl.Seal(nil, msg, &nonce, &key)

}
