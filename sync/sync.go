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

	"github.com/ejcx/passgo/pc"
	"github.com/ejcx/passgo/pio"
)

var (
	underAttack = "You are under attack! Your public key has changed"
)

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
	_, err = exec.Command("git", "init").Output()
	if err != nil {
		log.Fatalf("Could not initialize git repo: %s", err.Error())
	}
	configFile := pio.ConfigFileName[1:]
	siteFile := pio.SiteFileName[1:]
	_, err = exec.Command("git", "add", configFile).Output()
	if err != nil {
		log.Fatalf("Could not add %s: %s", configFile, err.Error())
	}
	_, err = exec.Command("git", "add", siteFile).Output()
	if err != nil {
		log.Fatalf("Could not add %s: %s", siteFile, err.Error())
	}
	_, err = exec.Command("git", "commit", "-m", "Do not pass go do not collect $200.").Output()
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
	exec.Command("git", "remote", "remove", "pass-origin").Output()
	_, err = exec.Command("git", "remote", "add", "pass-origin", remoteUrl).Output()
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
	_, err = exec.Command("git", "push", "-u", "pass-origin", "master").Output()
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
	_, err = exec.Command("git", "pull").Output()
	if err != nil {
		log.Fatalf("Could not pull changes: %s", err.Error())
	}
	verifyPubKey()
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
	_, err = exec.Command("git", "clone", repo, ".passgo").Output()
	if err != nil {
		log.Fatalf("Could not clone repo: %s", err.Error())
	}
	verifyPubKey()
}

// InsertCommit is used to create a new commit with an insert message.
func InsertCommit(name string) {
	commit(fmt.Sprintf("Inserted site %s", name))
}

// RenameCommit is used to create a new commit with a rename commit message.
func RenameCommit(from, to string) {
	commit(fmt.Sprintf("Renamed site %s to %s", from, to))
}

// RemoveCommit is used to create a new commit with a remove commit message.
func RemoveCommit(name string) {
	commit(fmt.Sprintf("Removed site %s", name))
}

// RegenerateCommit is used to create a new commit with a regenerate message.
func RegenerateCommit(name string) {
	commit(fmt.Sprintf("Regenerated password for site %s", name))
}

func verifyPubKey() {
	c, err := pio.ReadConfig()
	if err != nil {
		log.Fatalf("Could not read config: %s", err.Error())
	}

	pass, err := pio.PromptPass("Enter master password")
	if err != nil {
		log.Fatalf("Could not get master password: %s", err.Error())
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
		log.Fatalf(underAttack)
	}
}
func commit(msg string) {
	d, err := pio.GetPassDir()
	if err != nil {
		log.Fatalf("Could not get pass dir", err.Error())
	}
	err = os.Chdir(d)
	if err != nil {
		log.Fatalf("Could not change to pass directory: %s", err.Error())
	}
	_, err = exec.Command("git", "add", "-u").Output()
	if err != nil {
		log.Fatalf("Could not add files for commit: %s", err.Error())
	}
	_, err = exec.Command("git", "commit", "-m", msg).Output()
	if err != nil {
		log.Fatalf("Could not commit change: %s", err.Error())
	}
}
