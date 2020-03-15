package yubikey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/kreuzwerker/yess/encrypt"
	"github.com/kreuzwerker/yess/result"
	"github.com/pkg/errors"
	"pault.ag/go/ykpiv"
)

const (
	errFailedToDecryptOnDevice             = "failed to decrypt on device"
	errFailedToDecryptShare                = "failed to decrypt share"
	errFailedToGenerateEphemeralECCKeypair = "failed to generate ephemeral keypair"
	errFailedToGetKeyManagement            = "failed to get key management PIV slot - maybe no certificate is present"
	errFailedToGetSerial                   = "failed to get serial from device"
	errFailedToInitializeYubikey           = "failed to initialize Yubikey"
	errFailedToLogin                       = "failed to log into Yubikey (%d retries remaining)"
	errUnknownPublicKeyType                = "unknown public key type %v"
)

// Yubikey represents a Yubikey in PIV mode
type Yubikey struct {
	device  *ykpiv.Yubikey
	Expiry  string
	Issuer  string
	Serial  uint32
	slot    *ykpiv.Slot
	Subject string
}

var Debug func(string, ...interface{})

// New will initialize a PIV client for a Yubikey with the given PIN
func New(pin string) (*Yubikey, error) {

	piv, err := ykpiv.New(ykpiv.Options{
		Reader: "Yubico YubiKey",
		PIN:    &pin,
	})

	if err != nil {
		return nil, errors.Wrapf(err, errFailedToInitializeYubikey)
	}

	serial, err := piv.Serial()

	if err != nil {
		return nil, errors.Wrapf(err, errFailedToGetSerial)
	}

	yubikey := &Yubikey{
		device: piv,
		Serial: serial,
	}

	if Debug != nil {
		Debug("connecting to Yubikey %d with PIN %q", serial, pin)
	}

	if err := piv.Login(); err != nil {
		retries, _ := piv.PINRetries()
		return nil, errors.Wrapf(err, errFailedToLogin, retries)
	}

	slot, err := piv.KeyManagement()

	if err != nil {
		return nil, errors.Wrapf(err, errFailedToGetKeyManagement)
	}

	yubikey.slot = slot

	cert := slot.Certificate

	yubikey.Expiry = cert.NotAfter.Format(time.RFC3339)
	yubikey.Issuer = cert.Issuer.String()
	yubikey.Subject = cert.Subject.String()

	return yubikey, nil

}

// Close closes the connection to the Yubikey
func (y *Yubikey) Close() error {
	return y.device.Close()
}

// Decrypt decrypts a given part, yielding the plaintext share
func (y *Yubikey) Decrypt(p *result.Part) ([]byte, error) {

	pk, err := p.Key()

	if err != nil {
		return nil, err
	}

	switch t := pk.(type) {
	case *ecdsa.PublicKey:
		return y.decryptECC(t, p)
	default:
		return nil, fmt.Errorf(errUnknownPublicKeyType, t)
	}

}

// decryptECC decrypts a given part using ECC keys, yielding the plaintext share
func (y *Yubikey) decryptECC(ekp *ecdsa.PublicKey, p *result.Part) ([]byte, error) {

	// marshal the public key into the expected ANSI X9.62 format - see https://pkg.go.dev/pault.ag/go/ykpiv?tab=doc#Slot.Decrypt
	octet := elliptic.Marshal(ekp.Curve, ekp.X, ekp.Y)

	// decrypt, yielding the shared ephemeral key
	sk, err := y.slot.Decrypt(nil, octet, nil)

	if err != nil {
		return nil, errors.Wrapf(err, errFailedToDecryptOnDevice)
	}

	if Debug != nil {
		Debug("decrypting with ECC using SK %x", sk)
	}

	// decrypt the ciphertext share with the shared ephemeral key
	share, ok := encrypt.Decrypt(sk, p.Share)

	if !ok {
		return nil, fmt.Errorf(errFailedToDecryptShare)
	}

	if Debug != nil {
		Debug("decrypted share %x", share)
	}

	return share, nil

}

// Encrypt encrypts the given share into a Result
func (y *Yubikey) Encrypt(msg []byte) (*result.Part, error) {

	if Debug != nil {
		Debug("encrypting plaintext share %x", msg)
	}

	switch t := y.slot.Public().(type) {
	case *ecdsa.PublicKey:
		return y.encryptECC(t, msg)
	default:
		return nil, fmt.Errorf(errUnknownPublicKeyType, t)
	}

}

// encryptECC encrypts the given share using ECC keys into a Result
func (y *Yubikey) encryptECC(dkp *ecdsa.PublicKey, msg []byte) (*result.Part, error) {

	var (
		ekp *ecdsa.PublicKey
		sk  *big.Int
	)

	{

		// generate ephemeral keypair
		eks, px, py, err := elliptic.GenerateKey(dkp.Curve, rand.Reader)

		if err != nil {
			return nil, errors.Wrapf(err, errFailedToGenerateEphemeralECCKeypair)
		}

		// the ecsda structure is used due to native marshalling capabilities in package X509
		ekp = &ecdsa.PublicKey{
			X:     px,
			Y:     py,
			Curve: dkp.Curve,
		}

		// perform key exchange
		sk, _ = dkp.Curve.ScalarMult(dkp.X, dkp.Y, eks)

	}

	if Debug != nil {
		Debug("encrypting with ECC using SK %x", sk)
	}

	// encrypt the plaintext share with the shared ephemeral key
	share := encrypt.Encrypt(sk.Bytes(), msg)

	if Debug != nil {
		Debug("encrypted share %x", share)
	}

	result := &result.Part{
		Device:  "Yubikey", // TODO: get this from device
		Expiry:  y.Expiry,
		Issuer:  y.Issuer,
		Serial:  y.Serial,
		Share:   share,
		Subject: y.Subject,
	}

	if err := result.AddKey(ekp); err != nil {
		return nil, err
	}

	return result, nil

}
