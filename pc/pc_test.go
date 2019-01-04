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
		t.Fatalf("Could not generate password: %s", err)
	}
	if len(pass) == 0 {
		t.Fatalf("Bad length of password. Should never be 0")
	}
}

func TestGenerateImpossiblePassword(t *testing.T) {
	ps := &PasswordSpecs{
		NeedsUpper:  true,
		NeedsLower:  true,
		NeedsSymbol: true,
		NeedsDigit:  true,
	}
	_, err := GeneratePassword(ps, 3)
	if err == nil {
		t.Fatalf("Impossible password request did not throw an error")
	}
}

func TestGenerateShortPassword(t *testing.T) {
	ps := &PasswordSpecs{
		NeedsUpper:  true,
		NeedsLower:  true,
		NeedsSymbol: true,
		NeedsDigit:  true,
	}
	pass, err := GeneratePassword(ps, 4)
	if err != nil {
		t.Fatalf("Could not generate password: %s", err)
	}
	if len(pass) != 4 {
		t.Fatalf("Bad length of password. Should be 4")
	}
}
