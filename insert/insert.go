// Package insert handles adding a new site to the password store.
package insert

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/ejcx/passgo/pc"
	"github.com/ejcx/passgo/pio"
	"github.com/ejcx/passgo/sync"
	"golang.org/x/crypto/nacl/box"
)

const (
	// PassPrompt is the string formatter that should be used
	// when prompting for a password.
	PassPrompt = "Enter password for %s"
)

// Insert is used to add a new entry to the vault.
func Insert(name string) {
	var c pio.ConfigFile
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Could not generate site key: %s", err.Error())
	}

	config, err := pio.GetConfigPath()
	if err != nil {
		log.Fatalf("Could not get config file name: %s", err.Error())
	}

	// Read the master public key.
	configContents, err := ioutil.ReadFile(config)
	if err != nil {
		log.Fatalf("Could not get config file contents: %s", err.Error())
	}

	err = json.Unmarshal(configContents, &c)
	if err != nil {
		log.Fatalf("Could not unmarshal config file contents: %s", err.Error())
	}

	masterPub := c.MasterPubKey

	sitePass, err := pio.PromptPass(fmt.Sprintf("Enter password for %s", name))
	if err != nil {
		log.Fatalf("Could not get password for site: %s", err.Error())
	}

	passSealed, err := pc.SealAsym([]byte(sitePass), &masterPub, priv)

	si := pio.SiteInfo{
		PubKey:     *pub,
		Name:       name,
		PassSealed: passSealed,
	}

	err = si.AddSite()
	if err != nil {
		log.Fatalf("Could not save site file: %s", err.Error())
	}
	sync.InsertCommit(name)
}
