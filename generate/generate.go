package generate

import (
	"log"

	"github.com/ejcx/passgo/pc"
)

var (
	defaultPwLen = 24
)

// Generate will return a securely generated password. It uses the environment
// variable PASSGO_GENERATE_PASSWORD_LENGTH to determine the length, otherwise
// it defaults to 24 characters long.
func Generate(pwlen int) string {
	if pwlen < 1 {
		pwlen = defaultPwLen
	}
	// By default, we should generate a strog password that needs everything
	specs := &pc.PasswordSpecs{
		NeedsUpper:  true,
		NeedsLower:  true,
		NeedsSymbol: true,
		NeedsDigit:  true,
	}
	pass, err := pc.GeneratePassword(specs, pwlen)
	if err != nil {
		log.Fatalf("Could not generate password: %s", err.Error())
	}
	return pass
}
