// Package edit provides functionality to edit sites that have
// already been added to the password store. It should not
// remove sites or make changes without the consent of the
// user and MUST always regenerate a new key and reencrypt
// the data that is edited.
package edit

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"

	"golang.org/x/crypto/nacl/box"

	"github.com/ejcx/passgo/pc"
	"github.com/ejcx/passgo/pio"
	"github.com/ejcx/passgo/sync"
)

// Remove is used to remove a site entry from the password vault given a path.
func Remove(path string) {
	vault := pio.GetVault()
	pathIndex := -1
	for jj, siteInfo := range vault {
		if siteInfo.Name == path {
			pathIndex = jj
			break
		}
	}
	if pathIndex == -1 {
		log.Fatalf("Could not find %s in vault", path)
	}
	vault = append(vault[:pathIndex], vault[pathIndex+1:]...)
	err := pio.UpdateVault(vault)
	if err != nil {
		log.Fatalf("Could not update password vault: %s", err.Error())
	}
	sync.RemoveCommit(path)
}

// Edit is used to change the password of a site. New keys MUST be generated.
func Edit(path string) {
	vault := pio.GetVault()
	for jj, siteInfo := range vault {
		if siteInfo.Name == path {
			newPass, err := pio.PromptPass(fmt.Sprintf("Enter new password for %s", path))
			if err != nil {
				log.Fatalf("Could not get new password for %s: %s", path, err.Error())
			}
			newSiteInfo := reencrypt(siteInfo, newPass)
			vault[jj] = newSiteInfo
			err = pio.UpdateVault(vault)
			if err != nil {
				log.Fatalf("Could not edit %s: %s", path, err.Error)
			}
			sync.RegenerateCommit(path)
		}
	}
}

// Rename will take an vault name and change the name.
func Rename(path string) {
	vault := pio.GetVault()
	for jj, siteInfo := range vault {
		if siteInfo.Name == path {
			newName, err := pio.Prompt(fmt.Sprintf("Enter new site name for %s:", path))
			if err != nil {
				log.Fatalf("Could not get new site name from user: %s", err.Error())
			}
			vault[jj] = pio.SiteInfo{
				PubKey:     siteInfo.PubKey,
				PassSealed: siteInfo.PassSealed,
				Name:       newName,
			}
			err = pio.UpdateVault(vault)
			if err != nil {
				log.Fatalf("Could not renmae %s: %s", path, err.Error)
			}
			sync.RenameCommit(path, newName)
		}
	}
}

// reencrypt takes in a SiteInfo and will return a new SiteInfo that has been safely reencrypted
func reencrypt(s pio.SiteInfo, newPass string) pio.SiteInfo {
	var c pio.ConfigFile
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Could not generate new keys: %s", err.Error())
	}
	config, err := pio.GetConfigPath()
	if err != nil {
		log.Fatalf("Could not get config file name: %s", err.Error())
	}
	configContents, err := ioutil.ReadFile(config)
	if err != nil {
		log.Fatalf("Could not read contents of config: %s", err.Error())
	}
	err = json.Unmarshal(configContents, &c)
	if err != nil {
		log.Fatalf("Could not unmarshal config file contents for reencrypt: %s", err.Error())
	}
	masterPub := c.MasterPubKey

	passSealed, err := pc.SealAsym([]byte(newPass), &masterPub, priv)
	if err != nil {
		log.Fatalf("Could not seal new site password: %s", err.Error())
	}
	return pio.SiteInfo{
		PubKey:     *pub,
		Name:       s.Name,
		PassSealed: passSealed,
	}
}
