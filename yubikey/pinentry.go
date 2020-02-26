package yubikey

import (
	"golang.org/x/crypto/ssh/terminal"
)

type file interface {
	Fd() uintptr
}

const defaultPIN = "123456"

// PIN calls the msg function and provides PIN entry over the keyboard
func PIN(msg func(), in file) (string, error) {

	msg()

	pin, err := terminal.ReadPassword(int(in.Fd()))

	if err != nil {
		return "", err
	}

	if pin == nil {
		return defaultPIN, nil
	}

	return string(pin), nil

}
