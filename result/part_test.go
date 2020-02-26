package result

import (
	"crypto/ecdsa"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddAndGetKey(t *testing.T) {

	assert := assert.New(t)

	encoding := base64.StdEncoding

	for k, v := range map[string]string{
		`MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEs8WjfkQMzZaaCj7UltEtzLDJwdox1QhFPMQBDqJN0EhT/egUfo+2gC4ibWGpH8PsKrJKJP+F3OIQcX0ZTbUNVg==`:                                     "P-256",
		`MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEWW5+qZV4rgceOFHw/M/kxpE/5DrQyben5vDwM0cxNCt2dpoNIksQloDnrE58gVVl0kKl5zXQ7zUNYsWLr//rveBHiFEVcYhZOiahMELPa0QqPWJR0+50kCxJ3G9btKbX`: "P-384",
	} {

		out, err := encoding.DecodeString(k)

		assert.NoError(err)

		part := &Part{
			PublicKey: out,
		}

		key, err := part.Key()

		assert.NoError(err)

		pk := key.(*ecdsa.PublicKey)

		assert.Equal(v, pk.Params().Name)

		part = new(Part)

		part.AddKey(pk)

		assert.Equal(out, part.PublicKey)

	}

}
