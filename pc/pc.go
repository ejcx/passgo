// Package pc provides crypto functions for use by passgo. The purpose
// of pc is to provide safe interfaces that factor confusing
// and common programming errors away from programmers.
package pc

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"

	"github.com/f06ybeast/passgo/pio"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

var (
	// DigitLowerBound is the ascii digit lower bound.
	DigitLowerBound = 48
	// DigitUpperBound is the ascii digit upper bound.
	DigitUpperBound = 57
	// UpperCaseLowerBound is the ascii upper case lower bound.
	UpperCaseLowerBound = 65
	// UpperCaseUpperBound is the ascii upper case upper bound.
	UpperCaseUpperBound = 90
	// LowerCaseLowerBound is the ascii lower case lower bound.
	LowerCaseLowerBound = 97
	// LowerCaseUpperBound is the ascii lower case upper bound.
	LowerCaseUpperBound = 122

	// There are four groups of symbols in ascii table
	// It doesn't make sense to over engineer something
	// so just keep track of all the groups.

	// SymbolGrp1LowerBound is the ascii lowerbound of the first symbol grp.
	SymbolGrp1LowerBound = 33
	// SymbolGrp1UpperBound is the ascii lowerbound of the first symbol grp.
	SymbolGrp1UpperBound = 47
	// SymbolGrp2LowerBound is the ascii lowerbound of the first symbol grp.
	SymbolGrp2LowerBound = 58
	// SymbolGrp2UpperBound is the ascii lowerbound of the first symbol grp.
	SymbolGrp2UpperBound = 64
	// SymbolGrp3LowerBound is the ascii lowerbound of the first symbol grp.
	SymbolGrp3LowerBound = 91
	// SymbolGrp3UpperBound is the ascii lowerbound of the first symbol grp.
	SymbolGrp3UpperBound = 96
	// SymbolGrp4LowerBound is the ascii lowerbound of the first symbol grp.
	SymbolGrp4LowerBound = 123
	// SymbolGrp4UpperBound is the ascii lowerbound of the first symbol grp.
	SymbolGrp4UpperBound = 126
)

// PasswordSpecs indicates specifications for a desired generated password.
type PasswordSpecs struct {
	NeedsUpper  bool
	NeedsLower  bool
	NeedsSymbol bool
	NeedsDigit  bool
}

// Seal wraps that AEAD interface secretbox Seal and safely
// generates a random nonce for developers. This change to
// seal eliminates the risk of programmers reusing nonces.
func Seal(key *[32]byte, message []byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	return secretbox.Seal(nonce[:], message, &nonce, key), nil
}

// SealAsym wraps that AEAD interface box.Seal and safely generates
// a random nonce for developers. This change to seal eliminates
// the risk of programmers reusing nonces.
func SealAsym(message []byte, pub *[32]byte, priv *[32]byte) (out []byte, err error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	sealedBytes := box.Seal(out, message, &nonce, pub, priv)
	return append(nonce[:], sealedBytes...), nil
}

// OpenAsym wraps the AEAD interface box.Open
func OpenAsym(ciphertext []byte, pub, priv *[32]byte) (out []byte, err error) {
	var nonce [24]byte
	/* DEBUG; hadn't added `UserSealed` to `sites` @ pio.go, so `cryptext` slice failed
	fmt.Printf("FAILs @ OpenAsym - ciphertext[:24] \n%v\n", ciphertext[:24])
	fmt.Printf("FAILs @ OpenAsym - nonce[:] \n%v\n", nonce[:])
	var input string
	fmt.Scanln(&input)
	*/
	copy(nonce[:], ciphertext[:24])
	out, ok := box.Open(out[:0], ciphertext[24:], &nonce, pub, priv)
	if !ok {
		err = errors.New("Unable to decrypt message")
	}
	return
}

// Open wraps the AEAD interface secretbox.Open
func Open(key *[32]byte, ciphertext []byte) (message []byte, err error) {
	var nonce [24]byte
	copy(nonce[:], ciphertext[:24])
	message, ok := secretbox.Open(message[:0], ciphertext[24:], &nonce, key)
	if !ok {
		err = errors.New("Unable to decrypt message")
	}
	return
}

// Scrypt is a wrapper around scrypt.Key that performs the Scrypt
// algorithm on the input with opinionated defaults.
func Scrypt(pass, salt []byte) (key [32]byte, err error) {
	keyBytes, err := scrypt.Key(pass, salt, 262144, 8, 1, 32)
	copy(key[:], keyBytes)
	return
}

// GetMasterKey is used to prompt user's for their password, read the
// user's passgo config file and decrypt the master private key.
func GetMasterKey() (masterPrivKey [32]byte) {
	pass, err := pio.PromptPass(pio.MasterPassPrompt)
	if err != nil {
		log.Fatalf("Could not get master password: %s", err.Error())
	}
	c, err := pio.GetConfigPath()
	if err != nil {
		log.Fatalf("Could not get config file: %s", err.Error())
	}

	var configFile pio.ConfigFile
	configFileBytes, err := ioutil.ReadFile(c)
	if err != nil {
		log.Fatalf("Could not read config file: %s", err.Error())
	}
	err = json.Unmarshal(configFileBytes, &configFile)
	if err != nil {
		log.Fatalf("Could not read unmarshal config file: %s", err.Error())
	}
	masterKey, err := Scrypt([]byte(pass), configFile.MasterPassKeySalt[:])
	if err != nil {
		log.Fatalf("Could not create master key: %s", err.Error())
	}

	masterPrivKeySlice, err := Open(&masterKey, configFile.MasterKeyPrivSealed)

	copy(masterPrivKey[:], masterPrivKeySlice)
	if err != nil {
		log.Fatalf("Could not decrypt private key: %s", err.Error())
	}
	return
}

// Satisfied will determine if a PasswordSpecs type indicates it no longer
// needs any more specs.
func (s *PasswordSpecs) Satisfied() bool {
	return !s.NeedsDigit && !s.NeedsUpper && !s.NeedsLower && !s.NeedsSymbol
}
func checkBound(letter byte, lowerBound, upperBound int) bool {
	if int(letter) >= lowerBound && int(letter) <= upperBound {
		return true
	}
	return false
}
func isASCIIDigit(letter byte) bool {
	return checkBound(letter, DigitLowerBound, DigitUpperBound)
}
func isASCIIUpper(letter byte) bool {
	return checkBound(letter, UpperCaseLowerBound, UpperCaseUpperBound)
}
func isASCIILower(letter byte) bool {
	return checkBound(letter, LowerCaseLowerBound, LowerCaseUpperBound)
}
func isASCIISymbol(letter byte) bool {
	grp1 := checkBound(letter, SymbolGrp1LowerBound, SymbolGrp1UpperBound)
	grp2 := checkBound(letter, SymbolGrp2LowerBound, SymbolGrp2UpperBound)
	grp3 := checkBound(letter, SymbolGrp3LowerBound, SymbolGrp3UpperBound)
	grp4 := checkBound(letter, SymbolGrp4LowerBound, SymbolGrp4UpperBound)
	return grp1 || grp2 || grp3 || grp4
}
func updateSpec(specs *PasswordSpecs, letter byte) {
	if isASCIIDigit(letter) {
		specs.NeedsDigit = false
	} else if isASCIIUpper(letter) {
		specs.NeedsUpper = false
	} else if isASCIILower(letter) {
		specs.NeedsLower = false
	} else if isASCIISymbol(letter) {
		specs.NeedsSymbol = false
	}
}

// GeneratePassword is used to generate a password like string securely.
// GeneratePassword has no upper limit to the length of a password that
// it can generate, but is restricted by the size of int.
// It requires generation of a string password that has a upper case
// letter, a lower case letter, a symbol, and a number.
//
// It works by reading a big block of randomness from the crypto rand
// package and searching for printable characters. It will continue
// to  read chunks of randomness until it has found a password that
// meets the specifications of the PasswordSpec passed in to the func.
func GeneratePassword(specs *PasswordSpecs, passlen int) (pass string, err error) {
	var letters [2048]byte
	for {
		if passlen <= len(pass) {
			if specs.Satisfied() {
				return pass, nil
			}
		}
		_, err = rand.Read(letters[:])
		if err != nil {
			return
		}
		for _, letter := range letters {
			if passlen <= len(pass) {
				if specs.Satisfied() {
					return pass, nil
				}
			}
			// Check to make sure that the letter is inside
			// the range of printable characters
			if letter > 32 && letter < 127 {
				pass += string(letter)
			}
			updateSpec(specs, letter)
		}
	}
}

// GetSitesIntegrity is used to update the sites vault integrity file.
func GetSitesIntegrity() pio.ConfigFile {
	c, err := pio.ReadConfig()
	if err != nil {
		log.Fatalf("Could not read config: %s", err.Error())
	}
	pass, err := pio.PromptPass(pio.MasterPassPrompt)
	if err != nil {
		log.Fatalf("Could not get master password: %s", err.Error())
	}
	vaultBytes := pio.GetSiteFileBytes()

	siteHmacKey, err := Scrypt([]byte(pass), c.SiteHmacSalt[:])
	if err != nil {
		log.Fatalf("Could not generate site hmac key: %s", err.Error())
	}
	mac := hmac.New(sha256.New, siteHmacKey[:])
	_, err = mac.Write(vaultBytes)
	if err != nil {
		log.Fatalf("Could not write to hmac: %s", err.Error())
	}
	vaultMac := mac.Sum(nil)
	c.SiteHmac = vaultMac
	return c
}

// GenHexString will generate a random 32 character hex string.
func GenHexString() (string, error) {
	var b [16]byte
	_, err := rand.Read(b[:])
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
