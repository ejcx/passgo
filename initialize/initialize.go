package initialize

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"log"
	"os"

	"github.com/ejcx/passgo/pc"
	"github.com/ejcx/passgo/pio"
	"github.com/ejcx/passgo/sync"
	"golang.org/x/crypto/nacl/box"
)

const (
	saltLen     = 32
	configFound = "A passgo config file was already found."
)

// Init will initialize a new password vault in the home directory.
func Init() {
	var needsDir bool
	var hasConfig bool
	var hasVault bool

	if dirExists, err := pio.PassDirExists(); err == nil {
		if !dirExists {
			needsDir = true
		} else {
			if _, err := pio.PassConfigExists(); err == nil {
				hasConfig = true
			}
			if _, err := pio.SitesVaultExists(); err == nil {
				hasVault = true
			}
		}
	}

	passDir, err := pio.GetPassDir()
	if err != nil {
		log.Fatalf("Could not get pass dir: %s", err.Error())
	}
	sitesFile, err := pio.GetSitesFile()
	if err != nil {
		log.Fatalf("Could not get sites dir: %s", err.Error())
	}
	configFile, err := pio.GetConfigPath()
	if err != nil {
		log.Fatalf("Could not get pass config: %s", err.Error())
	}

	if needsDir {
		err = os.Mkdir(passDir, 0755)
		if err != nil {
			log.Fatalf("Could not create passgo vault: %s", err.Error())
		}
	}

	// Don't just go around deleting things for users or prompting them
	// to delete things. Make them do this manaully. Maybe this saves 1
	// person an afternoon.
	if hasConfig {
		log.Fatalf(configFound)
	}

	config, err := os.Create(configFile)
	if err != nil {
		log.Fatalf("Could not create passgo config: %s", err.Error())
	}
	config.Close()

	// Handle creation and initialization of the site vault.
	if !hasVault {
		sf, err := os.Create(sitesFile)
		if err != nil {
			log.Fatalf("Could not create pass sites vault: %s", err.Error())
		}
		// Initialize an empty SiteFile
		siteFileContents := []byte("[]")
		_, err = sf.Write(siteFileContents)
		if err != nil {
			log.Fatalf("Could not save site file: %s", err.Error())
		}
		sf.Close()
	}

	pass, err := pio.PromptPass("Please enter a strong master password")
	if err != nil {
		log.Fatalf("Could not read password: %s", err.Error())
	}

	// Generate a master password salt.
	var keySalt [32]byte
	_, err = rand.Read(keySalt[:])
	if err != nil {
		log.Fatalf("Could not generate random salt: %s", err.Error())
	}

	// Create a new salt for encrypting public key.
	var hmacSalt [32]byte
	_, err = rand.Read(hmacSalt[:])
	if err != nil {
		log.Fatalf("Could not generate random salt: %s", err.Error())
	}

	// kdf the master password.
	passKey, err := pc.Scrypt([]byte(pass), keySalt[:])
	if err != nil {
		log.Fatalf("Could not generate master key from pass: %s", err.Error())
	}

	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Could not generate master key pair: %s", err.Error())
	}

	// Encrypt master private key with master password key.
	sealedMasterPrivKey, err := pc.Seal(&passKey, priv[:])
	if err != nil {
		log.Fatalf("Could not encrypt master key: %s", err.Error())
	}

	hmacKey, err := pc.Scrypt([]byte(pass), hmacSalt[:])
	if err != nil {
		log.Fatalf("Could not generate secondary key from pass: %s", err.Error())
	}

	// Keep an hmac of the public key alongside your public key so that malicious
	// servers can be detected.
	mac := hmac.New(sha256.New, hmacKey[:])
	_, err = mac.Write(pub[:])
	if err != nil {
		log.Fatalf("Could not write to hmac reader: %s", err.Error())
	}
	pubKeyHmac := mac.Sum(nil)

	var siteHmacSalt [32]byte
	_, err = rand.Read(siteHmacSalt[:])
	if err != nil {
		log.Fatalf("Could not generate site hmac salt")
	}

	passConfig := pio.ConfigFile{
		MasterKeyPrivSealed: sealedMasterPrivKey,
		PubKeyHmac:          pubKeyHmac,
		MasterPubKey:        *pub,
		MasterPassKeySalt:   keySalt,
		HmacSalt:            hmacSalt,
		SiteHmacSalt:        siteHmacSalt,
	}

	if err = passConfig.SaveFile(); err != nil {
		log.Fatalf("Could not write to config file: %s", err.Error())
	}

	sync.Initialize()
}
