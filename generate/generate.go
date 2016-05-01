package generate

import (
	"log"

	"github.com/ejcx/passgo/pc"
)

var (
	defaultPwLen = 24
)

// Generate will return a securely generated password.
// A default password length of 24 with be used if
//     1. No pwlen is supplied
//     2. pwlen is less than 1
//     3. pwlen is greater than 2^17(131,072)
// NOTE: passwords are only guaranteed to be *at least* pwlen in length
//       they may in fact be longer
func Generate(pwlen int) string {
	if pwlen < 1 || pwlen > 1<<17 {
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
