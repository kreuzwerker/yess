package result

import (
	"crypto/x509"

	"github.com/pkg/errors"
)

// Part represents one share of the secret. Except for the share and the public key field all fields are just present for informational purposes (even the expiry).
type Part struct {
	Device    string `json:"device"`    // Device identifies the device through it's vendor string
	Expiry    string `json:"expiry"`    // Expiry is the RFC3339 representation of the certificates expiry date
	Issuer    string `json:"issuer"`    // Issuer is the certificates isser
	PublicKey []byte `json:"publicKey"` // PublicKey is a PKIX (DER) representation of the public key used for the shared key exchange
	Serial    uint32 `json:"serial"`    // Serial is the devices serial number (often printed on the device itself)
	Share     []byte `json:"share"`     // Share is the encrypted Shamir share
	Subject   string `json:"subject"`   // Subject is the certificate subject
}

const (
	errFailedToMarshal   = "failed to marshal public key"
	errFailedToUnmarshal = "failed to unmarshal public key"
)

// AddKey marshals a supported public key into DER
func (p *Part) AddKey(pk interface{}) error {

	out, err := x509.MarshalPKIXPublicKey(pk)

	if err != nil {
		return errors.Wrapf(err, errFailedToMarshal)
	}

	p.PublicKey = out

	return nil

}

// Key unmarshals a supported public key from DER
func (p *Part) Key() (interface{}, error) {

	out, err := x509.ParsePKIXPublicKey(p.PublicKey)

	if err != nil {
		return nil, errors.Wrapf(err, errFailedToUnmarshal)
	}

	return out, nil

}
