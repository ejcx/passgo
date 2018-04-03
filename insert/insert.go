// Package insert handles adding a new site to the password store.
package insert

import (
	"crypto/rand"
	"encoding/json"
	"io/ioutil"
	"log"

	"github.com/ejcx/passgo/pc"
	"github.com/ejcx/passgo/sync"
	"github.com/f06ybeast/passgo/pio"
	"golang.org/x/crypto/nacl/box"
)

// Insert is used to insert a new site entry into the vault.
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

	s := pio.PromptCreds(name)
	masterPub := c.MasterPubKey
	userSealed, err := pc.SealAsym([]byte(s.User), &masterPub, priv)
	passSealed, err := pc.SealAsym([]byte(s.Pass), &masterPub, priv)

	si := pio.SiteInfo{
		PubKey:     *pub,
		Name:       name,
		PassSealed: passSealed,
		UserSealed: userSealed,
	}

	err = si.AddSite()
	if err != nil {
		log.Fatalf("Could not save site file: %s", err.Error())
	}
	sync.InsertCommit(name)
}

// File is used to add a new file entry to the vault.
func File(path, filename string) {
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

	fileBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatalf("Could not open and read file that is being encrypted: %s", err.Error())
	}

	fileSealed, err := pc.SealAsym([]byte(fileBytes), &masterPub, priv)
	if err != nil {
		log.Fatalf("Could not seal file bytes: %s", err.Error())
	}

	tokenFile, err := pc.GenHexString()
	if err != nil {
		log.Fatalf("Could not generate random string: %s", err.Error())
	}

	si := pio.SiteInfo{
		PubKey:   *pub,
		Name:     path,
		IsFile:   true,
		FileName: tokenFile,
	}

	err = si.AddFile(fileSealed, tokenFile)
	if err != nil {
		log.Fatalf("Could not save site file after file insert: %s", err.Error())
	}
	sync.InsertCommit(path)
}
