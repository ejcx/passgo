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

	"github.com/f06ybeast/passgo/pc"
	"github.com/f06ybeast/passgo/pio"
	"github.com/f06ybeast/passgo/sync"
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
				pio.LogF(err, "Could not get encrypted file path for deleting")
				fp := filepath.Join(encFileDir, siteInfo.FileName)
				err = os.Remove(fp)
				pio.LogF(err, "Attempted to remove file but was unable to")
			}
			break
		}
	}
	if pathIndex == -1 {
		log.Fatalf("Could not find %s in vault", path)
	}
	vault = append(vault[:pathIndex], vault[pathIndex+1:]...)
	err := pio.UpdateVault(vault)
	pio.LogF(err, "Could not update password vault")
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

// Edit is used to change the Creds (user/pass) of a site. New keys MUST be generated.
func Edit(path string) {
	vault := pio.GetVault()
	for jj, siteInfo := range vault {
		if siteInfo.Name == path {
			newSiteInfo := reencrypt(siteInfo, pio.PromptCreds(path))
			vault[jj] = newSiteInfo
			err := pio.UpdateVault(vault)
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
			newName, err := pio.Prompt(fmt.Sprintf("Enter new site name for %s", path))
			pio.LogF(err, "Could not get new site name from user")

			if newName == "" {
				log.Fatalln("A site name is REQUIRED.")
			}
			vault[jj] = pio.SiteInfo{
				PubKey:     siteInfo.PubKey,
				UserSealed: siteInfo.UserSealed,
				PassSealed: siteInfo.PassSealed,
				Name:       newName,
			}
			err = pio.UpdateVault(vault)
			if err != nil {
				log.Fatalf("Could not rename %s: %s", path, err)
			}
			sync.RenameCommit(path, newName)
		}
	}
}

// reencrypt takes in SiteInfo and (plaintext) Creds, and returns SiteInfo reencrypted.
func reencrypt(s pio.SiteInfo, site pio.Creds) pio.SiteInfo {
	var c pio.ConfigFile
	pub, priv, err := box.GenerateKey(rand.Reader)
	pio.LogF(err, "Could not generate new keys")

	config, err := pio.GetConfigPath()
	pio.LogF(err, "Could not get config file name")

	configContents, err := ioutil.ReadFile(config)
	pio.LogF(err, "Could not read contents of config")

	err = json.Unmarshal(configContents, &c)
	pio.LogF(err, "Could not unmarshall config file contents for reencrypt")

	masterPub := c.MasterPubKey
	b := make(map[string][]byte, 2)
	for k, v := range map[string]string{"username": site.User, "password": site.Pass} {
		b[k], err = pc.SealAsym([]byte(v), &masterPub, priv)
		pio.LogF(err, "Could not seal new site "+v)
	}

	return pio.SiteInfo{
		PubKey:     *pub,
		Name:       s.Name,
		UserSealed: b["username"],
		PassSealed: b["password"],
	}
}
