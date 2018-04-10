// Package insert handles adding a new site to the password store.
package insert

import (
	"crypto/rand"
	"encoding/json"
	"io/ioutil"

	"github.com/f06ybeast/passgo/pc"
	"github.com/f06ybeast/passgo/pio"
	"github.com/f06ybeast/passgo/sync"
	"golang.org/x/crypto/nacl/box"
)

// Insert is used to insert a new site entry into the vault.
func Insert(name string) {
	var c pio.ConfigFile
	pub, priv, err := box.GenerateKey(rand.Reader)
	pio.LogF(err, "Could not generate site key")

	config, err := pio.GetConfigPath()
	pio.LogF(err, "Could not get config file name")

	// Read the master public key.
	configContents, err := ioutil.ReadFile(config)
	pio.LogF(err, "Could not get config file contents")

	err = json.Unmarshal(configContents, &c)
	pio.LogF(err, "Could not unmarshal config file contents")

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
	pio.LogF(err, "Could not save site file")

	sync.InsertCommit(name)
}

// File is used to add a new file entry to the vault.
func File(path, filename string) {
	var c pio.ConfigFile
	pub, priv, err := box.GenerateKey(rand.Reader)
	pio.LogF(err, "Could not generate site key")

	config, err := pio.GetConfigPath()
	pio.LogF(err, "Could not get config file name")

	// Read the master public key.
	configContents, err := ioutil.ReadFile(config)
	pio.LogF(err, "Could not get config file contents")

	err = json.Unmarshal(configContents, &c)
	pio.LogF(err, "Could not unmarshal config file contents")

	masterPub := c.MasterPubKey

	fileBytes, err := ioutil.ReadFile(filename)
	pio.LogF(err, "Could not open and read file that is being encrypted")

	fileSealed, err := pc.SealAsym([]byte(fileBytes), &masterPub, priv)
	pio.LogF(err, "Could not seal file bytes")

	tokenFile, err := pc.GenHexString()
	pio.LogF(err, "Could not generate random string")

	si := pio.SiteInfo{
		PubKey:   *pub,
		Name:     path,
		IsFile:   true,
		FileName: tokenFile,
	}

	err = si.AddFile(fileSealed, tokenFile)
	pio.LogF(err, "Could not save site file after file insert")

	sync.InsertCommit(path)
}
