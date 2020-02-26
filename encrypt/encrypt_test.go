package encrypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeysMatter(t *testing.T) {

	assert := assert.New(t)

	a := Encrypt([]byte("a"), []byte("my secret"))
	b := Encrypt([]byte("b"), []byte("my secret"))
	c := Encrypt([]byte("a"), []byte("my secret"))

	assert.NotEqual(a, b)
	assert.Equal(a, c)

}

func TestEncryptDecrypt(t *testing.T) {

	assert := assert.New(t)

	a := Encrypt([]byte("a"), []byte("my secret"))

	out, ok := Decrypt([]byte("a"), a)

	assert.True(ok)
	assert.Equal("my secret", string(out))

	out, ok = Decrypt([]byte("b"), a)

	assert.False(ok)
	assert.Nil(out)

}
