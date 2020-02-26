package split

import (
	"fmt"
	"os"

	"github.com/kreuzwerker/yess/result"
	shamir "github.com/kreuzwerker/yess/share"
	"github.com/kreuzwerker/yess/yubikey"
	"github.com/pkg/errors"
)

const (
	errDuplicateDeviceUsed      = "duplicate device used (serial number %d)"
	errFailedToConnectToYubikey = "failed to connect to Yubikey"
	errFailedToEncrypt          = "failed to encrypt share"
	errInvalidDevice            = "invalid device added - it was not part of the original share group"
	logCandidateFound           = "candidate %d: serial %d, issuer %s, subject %s, expiry %s"
	logConnectAndEnterPIN       = "please connect one of these devices and enter PIN (or press enter to use the default PIN)"
	logPassedThresholdIssue     = "passed threshold, but share cannot be recovered yet (%s)"
	logSplitting                = "splitting secret into %d yubikeys"
)

type Split struct {
	out func(string, ...interface{})
}

func New(out func(string, ...interface{})) *Split {

	return &Split{
		out: out,
	}

}

func (s *Split) Combine(res *result.Result) ([]byte, error) {

	var (
		mapping = make(map[uint32]*result.Part)
		shares  [][]byte
	)

	for idx, part := range res.Parts {

		s.out(logCandidateFound,
			idx+1,
			part.Serial,
			part.Issuer,
			part.Subject,
			part.Expiry,
		)

		mapping[part.Serial] = part

	}

	for {

		pin, err := s.pin()

		if err != nil {
			return nil, err
		}

		y, err := yubikey.New(pin)

		if err != nil {
			return nil, errors.Wrapf(err, errFailedToConnectToYubikey)
		}

		part, ok := mapping[y.Serial]

		if !ok {
			return nil, errors.New(errInvalidDevice)
		}

		share, err := y.Decrypt(part)

		if err != nil {
			return nil, err
		}

		shares = append(shares, share)

		if len(shares) >= res.Threshold {

			secret, err := shamir.Combine(shares)

			if err != nil {
				s.out(logPassedThresholdIssue, err)
			}

			return secret, nil

		}

	}

}

func (s *Split) Split(secret []byte, parts, threshold int) (*result.Result, error) {

	mapping := make(map[uint32]interface{})

	result := &result.Result{
		Threshold: threshold,
	}

	shares, err := shamir.Split(secret, parts, threshold)

	if err != nil {
		return nil, err
	}

	s.out(logSplitting, parts)

	for _, share := range shares {

		pin, err := s.pin()

		if err != nil {
			return nil, err
		}

		y, err := yubikey.New(pin)

		if err != nil {
			return nil, errors.Wrapf(err, errFailedToConnectToYubikey)
		}

		part, err := y.Encrypt(share)

		if err != nil {
			return nil, errors.Wrapf(err, errFailedToConnectToYubikey)
		}

		if _, ok := mapping[part.Serial]; ok {
			return nil, fmt.Errorf(errDuplicateDeviceUsed, part.Serial)
		}

		mapping[part.Serial] = struct{}{}

		result.Parts = append(result.Parts, part)

		y.Close()

	}

	return result, nil

}

func (s *Split) pin() (string, error) {

	pin, err := yubikey.PIN(func() {
		s.out(logConnectAndEnterPIN)
	}, os.Stderr)

	if err != nil {
		return "", err
	}

	return pin, nil

}
