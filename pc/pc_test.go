package pc

import (
	"encoding/hex"
	"testing"
)

func TestGenHexString(t *testing.T) {
	g, err := GenHexString()
	if err != nil {
		t.Errorf("Could not generate hex string: %s", err)
	}
	_, err = hex.DecodeString(g)
	if err != nil {
		t.Errorf("Could not decode hex string: %s", err)
	}
}

func TestGeneratePassword(t *testing.T) {
	pass, err := GeneratePassword(&PasswordSpecs{}, 20)
	if err != nil {
		t.Errorf("Could not decode hex string: %s", err)
	}
	if len(pass) == 0 {
		t.Error("Bad length of password. Should never be 0")
	}
}
