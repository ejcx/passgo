// Package sync is used for syncing data with git. It is a super hacky wrapper
// around the exec package but shelling out will work just fine for what is
// necessary.

package sync

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/f06ybeast/passgo/pc"
	"github.com/f06ybeast/passgo/pio"
)

var (
	// IntegrityCommit is the standard message for integrity hash commits
	IntegrityCommit = "Updated integrity hash"

	underAttack      = "You are under attack! Your public key has changed."
	underAttackSites = "You are under attack! Your site file has changed."
)

// Initialize a new git repository in the user's home .passgo directory.
func Initialize() {
	d, err := pio.GetPassDir()
	pio.LogF(err, "Could not get pass dir")
	err = os.Chdir(d)
	pio.LogF(err, "Could not change to pass directory")
	_, err = exec.Command("git", "init").Output()
	pio.LogF(err, "Could not initialize git repo")
	configFile := pio.ConfigFileName
	siteFile := pio.SiteFileName
	_, err = exec.Command("git", "add", configFile).Output()
	if err != nil {
		log.Fatalf("Could not add %s: %s", configFile, err)
	}
	_, err = exec.Command("git", "add", siteFile).Output()
	if err != nil {
		log.Fatalf("Could not add %s: %s", siteFile, err)
	}
	_, err = exec.Command("git", "commit", "-m", "Do not pass go do not collect $200.").Output()
	pio.LogF(err, "Could not make initial commit")
}

// Remote will change where the repository is stored.
func Remote(remoteURL string) {
	d, err := pio.GetPassDir()
	pio.LogF(err, "Could not get pass dir")
	err = os.Chdir(d)
	pio.LogF(err, "Could not change to pass directory")
	// Remove previous remote. If there was none it will throw an error so just
	// ignore it. If it fails, adding pass-origin will fail.
	exec.Command("git", "remote", "remove", "pass-origin").Output()
	_, err = exec.Command("git", "remote", "add", "pass-origin", remoteURL).Output()
	if err != nil {
		log.Fatalf("Could not add remote %s: %s", remoteURL, err)
	}
}

// Push will push your changes to the remote repository.
func Push() {
	d, err := pio.GetPassDir()
	pio.LogF(err, "Could not get pass dir")
	err = os.Chdir(d)
	pio.LogF(err, "Could not change to pass directory")
	c := pc.GetSitesIntegrity()
	err = c.SaveFile()
	pio.LogF(err, "Could not save config file with hmac")
	Commit("Update integrity hash")
	_, err = exec.Command("git", "push", "-u", "pass-origin", "master").Output()
	pio.LogF(err, "Could not push changes")
}

// Pull will get changes from the remote repository.
func Pull() {
	d, err := pio.GetPassDir()
	pio.LogF(err, "Could not get pass dir")
	err = os.Chdir(d)
	pio.LogF(err, "Could not change to pass directory")
	_, err = exec.Command("git", "pull").Output()
	pio.LogF(err, "Could not pull changes")
	verifyIntegrity()
}

// Clone will copy a remote repository to your .passgo directory.
func Clone(repo string) {
	passdir, err := pio.GetPassDir()
	pio.LogF(err, "Could not get PASSGODIR")
	home := filepath.Base(passdir)
	err = os.Chdir(home)
	if err != nil {
		log.Fatalf("Could not change to directory %s: %s", home, err.Error())
	}
	_, err = exec.Command("git", "clone", repo, filepath.Dir(passdir)).Output()
	if err != nil {
		log.Fatalf("Could not clone repo %s: %s", passdir, err.Error())
	}
	Remote(repo)
	verifyIntegrity()

}

// InsertCommit is used to create a new commit with an insert message.
func InsertCommit(name string) {
	Commit(fmt.Sprintf("Insert site %s", name))
}

// RenameCommit is used to create a new commit with a rename commit message.
func RenameCommit(from, to string) {
	Commit(fmt.Sprintf("Rename site %s to %s", from, to))
}

// RemoveCommit is used to create a new commit with a remove commit message.
func RemoveCommit(name string) {
	Commit(fmt.Sprintf("Remove site %s", name))
}

// RegenerateCommit is used to create a new commit with a regenerate message.
func RegenerateCommit(name string) {
	Commit(fmt.Sprintf("Regenerate password for site %s", name))
}

func verifyIntegrity() {
	pass, err := pio.PromptPass(pio.MasterPassPrompt)
	pio.LogF(err, "Could not get master password")
	c, err := pio.ReadConfig()
	pio.LogF(err, "Could not get config file")
	hmacKey, err := pc.Scrypt([]byte(pass), c.HmacSalt[:])
	pio.LogF(err, "Could not generate public key")
	mac := hmac.New(sha256.New, hmacKey[:])
	_, err = mac.Write(c.MasterPubKey[:])
	pio.LogF(err, "Could not write to hmac reader")
	messageMac := mac.Sum(nil)
	if !hmac.Equal(messageMac, c.PubKeyHmac) {
		err = pio.CreateAttack()
		if err != nil {
			log.Fatalf("%s: %s", underAttack, err.Error())
		}
		log.Fatalf(underAttack)
	}

	// We also need to check the integrity of the sites file.
	vaultBytes := pio.GetSiteFileBytes()

	siteHmacKey, err := pc.Scrypt([]byte(pass), c.SiteHmacSalt[:])
	pio.LogF(err, "Could not generate site hmac key")
	mac = hmac.New(sha256.New, siteHmacKey[:])
	_, err = mac.Write(vaultBytes)
	pio.LogF(err, "Could not write to hmac")
	vaultMac := mac.Sum(nil)
	if !hmac.Equal(vaultMac, c.SiteHmac) {
		// Created the attacked file.
		err = pio.CreateAttack()
		if err != nil {
			log.Fatalf("%s: %s", underAttackSites, err)
		}
		log.Fatalf(underAttackSites)
	}
}

func Commit(msg string) {
	d, err := pio.GetPassDir()
	pio.LogF(err, "Could not get pass dir")
	err = os.Chdir(d)
	pio.LogF(err, "Could not change to pass directory")
	_, err = exec.Command("git", "add", "-u").Output()
	pio.LogF(err, "Could not add files for commit")
	exec.Command("git", "commit", "-m", msg).Output()
}
