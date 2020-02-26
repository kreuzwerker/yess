package result

import (
	"crypto/ecdsa"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResultLoadAndSave(t *testing.T) {

	assert := assert.New(t)

	json := `{
	"Parts": [
		{
			"device": "A",
			"expiry": "2021-02-25T00:00:00Z",
			"issuer": "CN=acme inc",
			"publicKey": "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAECgXCraDGX1xN8HfvOpGAPY2Jmp56bRBWLE0vIVxk4CsyDnPyiWF3Vq3gI1KsWaMZxyXRk+mUprPbbu32pUEv4/a9b7zYwte8lsL4n9DS92EKZbkqxSEa4Xd2kI2klZlz",
			"serial": 1,
			"share": "U/VNWIT1+ZqYwbwanJ/5FZITpP2xBQM2QQilK7uunh2K6gSRvcxnmFNtShebbh+9Xxd4dPZ+U3aqKx3IT3FSFtZL",
			"subject": "CN=mr. a"
		},
		{
			"device": "B",
			"expiry": "2021-02-26T00:00:00Z",
			"issuer": "CN=bcme inc",
			"publicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEs8WjfkQMzZaaCj7UltEtzLDJwdox1QhFPMQBDqJN0EhT/egUfo+2gC4ibWGpH8PsKrJKJP+F3OIQcX0ZTbUNVg==",
			"serial": 2,
			"share": "k9YI2Yzpr5gTYtuyu1giI5oeWSmFSOVxx82QinbCJJFRANuN4TvBKyQHsedca2ZrAYGm59ci1ZeE1A3F7MVP",
			"subject": "CN=ms. b"
		},
		{
			"device": "C",
			"expiry": "2021-02-27T00:00:00Z",
			"issuer": "CN=ccme inc",
			"publicKey": "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEWW5+qZV4rgceOFHw/M/kxpE/5DrQyben5vDwM0cxNCt2dpoNIksQloDnrE58gVVl0kKl5zXQ7zUNYsWLr//rveBHiFEVcYhZOiahMELPa0QqPWJR0+50kCxJ3G9btKbX",
			"serial": 3,
			"share": "6aWlG3fx2dpf6AeSnX7UMlFkdF0aBB6+nMRubqTCZloXvIXT+2spOu0nLs4EcOL3ChhUwv9wJodssUrI",
			"subject": "CN=mrs. c"
		}
	],
	"Threshold": 2
}`

	result, err := Load(strings.NewReader(";"))

	assert.EqualError(err, `failed to decode result: invalid character ';' looking for beginning of value`)
	assert.Nil(result)

	result, err = Load(strings.NewReader(json))

	assert.NoError(err)
	assert.NotNil(result)

	assert.Equal(2, result.Threshold)

	mapping := make(map[uint32]*Part)

	for _, part := range result.Parts {
		mapping[part.Serial] = part
	}

	assert.Equal(3, len(mapping))

	// a

	assert.Equal("A", mapping[1].Device)
	assert.Equal("2021-02-25T00:00:00Z", mapping[1].Expiry)
	assert.Equal("CN=acme inc", mapping[1].Issuer)

	key, _ := mapping[1].Key()
	assert.Equal("P-384", key.(*ecdsa.PublicKey).Params().Name)

	assert.Equal(uint32(1), mapping[1].Serial)
	assert.Equal(66, len(mapping[1].Share))
	assert.Equal("CN=mr. a", mapping[1].Subject)

	// b

	assert.Equal("B", mapping[2].Device)
	assert.Equal("2021-02-26T00:00:00Z", mapping[2].Expiry)
	assert.Equal("CN=bcme inc", mapping[2].Issuer)

	key, _ = mapping[2].Key()
	assert.Equal("P-256", key.(*ecdsa.PublicKey).Params().Name)

	assert.Equal(uint32(2), mapping[2].Serial)
	assert.Equal(63, len(mapping[2].Share))
	assert.Equal("CN=ms. b", mapping[2].Subject)

	// c

	assert.Equal("C", mapping[3].Device)
	assert.Equal("2021-02-27T00:00:00Z", mapping[3].Expiry)
	assert.Equal("CN=ccme inc", mapping[3].Issuer)

	key, _ = mapping[3].Key()
	assert.Equal("P-384", key.(*ecdsa.PublicKey).Params().Name)

	assert.Equal(uint32(3), mapping[3].Serial)
	assert.Equal(60, len(mapping[3].Share))
	assert.Equal("CN=mrs. c", mapping[3].Subject)

}
