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
	"os"
	"path/filepath"

	"golang.org/x/crypto/nacl/box"

	"github.com/ejcx/passgo/pc"
	"github.com/ejcx/passgo/sync"
	"github.com/f06ybeast/passgo/pio"
)

// Remove is used to remove a site entry from the password vault given a path.
func remove(path string, removeFile bool) {
	vault := pio.GetVault()
	pathIndex := -1
	for jj, siteInfo := range vault {
		if siteInfo.Name == path {
			pathIndex = jj
			if removeFile {
				if !siteInfo.IsFile {
					log.Fatalf("Attempting to remove a non-file entry. Use `passgo rm` not `passgo rmfile`")
				}
				encFileDir, err := pio.GetEncryptedFilesDir()
				if err != nil {
					log.Fatalf("Could not get encrypted file path for deleting: %s", err.Error())
				}
				fp := filepath.Join(encFileDir, siteInfo.FileName)
				err = os.Remove(fp)
				if err != nil {
					log.Fatalf("Attempted to remove file but was unable to: %s", err.Error())
				}
			}
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

// RemovePassword is called to remove a password entry.
func RemovePassword(path string) {
	remove(path, false)
}

// RemoveFile is called to remove a file and siteinfo entry.
func RemoveFile(path string) {
	remove(path, true)
}

// Edit is used to change the password of a site. New keys MUST be generated.
func Edit(path string) {
	vault := pio.GetVault()
	for jj, siteInfo := range vault {
		if siteInfo.Name == path {
			newPass, err := pio.PromptPass(fmt.Sprintf("Enter new password for %s", path))
			if err != nil {
				log.Fatalf("Could not get new password for %s: %s", path, err)
			}
			newSiteInfo := reencrypt(siteInfo, newPass)
			vault[jj] = newSiteInfo
			err = pio.UpdateVault(vault)
			if err != nil {
				log.Fatalf("Could not edit %s: %s", path, err)
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
				UserSealed: siteInfo.UserSealed,
				PassSealed: siteInfo.PassSealed,
				Name:       newName,
			}
			err = pio.UpdateVault(vault)
			if err != nil {
				log.Fatalf("Could not renmae %s: %s", path, err)
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
		UserSealed: s.UserSealed,
		PassSealed: passSealed,
	}
}
