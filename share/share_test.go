package share

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSplitAndCombine(t *testing.T) {

	assert := assert.New(t)

	parts, err := Split([]byte("my secret"), 4, 3)

	assert.NoError(err)

	res, err := Combine([][]byte{
		parts[0],
		parts[1],
	})

	assert.Error(err, "invalid hash, parts are missing")

	assert.Nil(res)

	fmt.Println(string(res))

	res, err = Combine([][]byte{
		parts[0],
		parts[1],
		parts[2],
	})

	assert.NoError(err)

	assert.Equal("my secret", string(res))

}
