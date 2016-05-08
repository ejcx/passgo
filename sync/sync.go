// Package sync is used for syncing data with git. It is a super hacky wrapper
// around the exec package but shelling out will work just fine for what is
// necessary.

package sync

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/ejcx/passgo/pc"
	"github.com/ejcx/passgo/pio"
)

var (
	// IntegrityCommit is the standard message for integrity hash commits
	IntegrityCommit = "Updated integrity hash"

	underAttack      = "You are under attack! Your public key has changed."
	underAttackSites = "You are under attack! Your site file has changed."
)

func run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var stderr, stdout bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stdout
	out := stdout.String()
	err := cmd.Run()
	if err != nil {
		return out, errors.New(stderr.String())
	}
	return out, nil
}

// Initialize a new git repository in the user's home .passgo directory.
func Initialize() {
	d, err := pio.GetPassDir()
	if err != nil {
		log.Fatalf("Could not get pass dir", err.Error())
	}
	err = os.Chdir(d)
	if err != nil {
		log.Fatalf("Could not change to pass directory: %s", err.Error())
	}
	_, err = run("git", "init")
	if err != nil {
		log.Fatalf("Could not initialize git repo: %s", err.Error())
	}
	configFile := pio.ConfigFileName
	siteFile := pio.SiteFileName
	_, err = run("git", "add", configFile)
	if err != nil {
		log.Fatalf("Could not add %s: %s", configFile, err.Error())
	}
	_, err = run("git", "add", siteFile)
	if err != nil {
		log.Fatalf("Could not add %s: %s", siteFile, err.Error())
	}
	_, err = run("git", "commit", "-m", "Do not pass go do not collect $200.")
	if err != nil {
		log.Fatalf("Could not make initial commit: %s", err.Error())
	}
}

// Remote will change where the repository is stored.
func Remote(remoteUrl string) {
	d, err := pio.GetPassDir()
	if err != nil {
		log.Fatalf("Could not get pass dir", err.Error())
	}
	err = os.Chdir(d)
	if err != nil {
		log.Fatalf("Could not change to pass directory: %s", err.Error())
	}
	// Remove previous remote. If there was none it will throw an error so just
	// ignore it. If it fails, adding pass-origin will fail.
	run("git", "remote", "remove", "pass-origin")
	_, err = run("git", "remote", "add", "pass-origin", remoteUrl)
	if err != nil {
		log.Fatalf("Could not add remote %s: %s", remoteUrl, err.Error())
	}
}

// Push will push your changes to the remote repository.
func Push() {
	d, err := pio.GetPassDir()
	if err != nil {
		log.Fatalf("Could not get pass dir", err.Error())
	}
	err = os.Chdir(d)
	if err != nil {
		log.Fatalf("Could not change to pass directory: %s", err.Error())
	}
	c := pc.GetSitesIntegrity()
	err = c.SaveFile()
	if err != nil {
		log.Fatalf("Could not save config file with hmac: %s", err.Error())
	}
	Commit("Updated integrity hash")
	_, err = run("git", "push", "-u", "pass-origin", "master")
	if err != nil {
		log.Fatalf("Could not push changes: %s", err.Error())
	}
}

// Pull will get changes from the remote repository.
func Pull() {
	d, err := pio.GetPassDir()
	if err != nil {
		log.Fatalf("Could not get pass dir", err.Error())
	}
	err = os.Chdir(d)
	if err != nil {
		log.Fatalf("Could not change to pass directory: %s", err.Error())
	}
	_, err = run("git", "pull")
	if err != nil {
		log.Fatalf("Could not pull changes: %s", err.Error())
	}
	verifyIntegrity()
}

// Clone will copy a remote repository to your .passgo directory.
func Clone(repo string) {
	home, err := pio.GetHomeDir()
	if err != nil {
		log.Fatalf("Could not get home directory: %s", err.Error())
	}
	err = os.Chdir(home)
	if err != nil {
		log.Fatalf("Could not change to home directory: %s", err.Error())
	}
	_, err = run("git", "clone", repo, ".passgo")
	if err != nil {
		log.Fatalf("Could not clone repo: %s", err.Error())
	}
	Remote(repo)
	verifyIntegrity()

}

// InsertCommit is used to create a new commit with an insert message.
func InsertCommit(name string) {
	Commit(fmt.Sprintf("Inserted site %s", name))
}

// RenameCommit is used to create a new commit with a rename commit message.
func RenameCommit(from, to string) {
	Commit(fmt.Sprintf("Renamed site %s to %s", from, to))
}

// RemoveCommit is used to create a new commit with a remove commit message.
func RemoveCommit(name string) {
	Commit(fmt.Sprintf("Removed site %s", name))
}

// RegenerateCommit is used to create a new commit with a regenerate message.
func RegenerateCommit(name string) {
	Commit(fmt.Sprintf("Regenerated password for site %s", name))
}

func verifyIntegrity() {
	pass, err := pio.PromptPass(pio.MasterPassPrompt)
	if err != nil {
		log.Fatalf("Could not get master password: %s", err.Error())
	}
	c, err := pio.ReadConfig()
	if err != nil {
		log.Fatalf("Could not get config file.", err.Error())
	}
	hmacKey, err := pc.Scrypt([]byte(pass), c.HmacSalt[:])
	if err != nil {
		log.Fatalf("Could not generate public key: %s", err.Error())
	}

	mac := hmac.New(sha256.New, hmacKey[:])
	_, err = mac.Write(c.MasterPubKey[:])
	if err != nil {
		log.Fatalf("Could not write to hmac reader: %s", err.Error())
	}
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
	if err != nil {
		log.Fatalf("Could not generate site hmac key: %s", err.Error())
	}
	mac = hmac.New(sha256.New, siteHmacKey[:])
	_, err = mac.Write(vaultBytes)
	if err != nil {
		log.Fatalf("Could not write to hmac: %s", err.Error())
	}
	vaultMac := mac.Sum(nil)
	if !hmac.Equal(vaultMac, c.SiteHmac) {
		// Created the attacked file.
		err = pio.CreateAttack()
		if err != nil {
			log.Fatalf("%s: %s", underAttackSites, err.Error())
		}
		log.Fatalf(underAttackSites)
	}
}

func Commit(msg string) {
	d, err := pio.GetPassDir()
	if err != nil {
		log.Fatalf("Could not get pass dir", err.Error())
	}
	err = os.Chdir(d)
	if err != nil {
		log.Fatalf("Could not change to pass directory: %s", err.Error())
	}
	_, err = run("git", "add", "-u")
	if err != nil {
		log.Fatalf("Could not add files for commit: %s", err.Error())
	}
	run("git", "commit", "-m", msg)
}
