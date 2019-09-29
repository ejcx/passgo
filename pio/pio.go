package pio

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/atotto/clipboard"

	"golang.org/x/crypto/ssh/terminal"
)

const (
	PASSGODIR = "PASSGODIR"
	// ConfigFileName is the name of the passgo config file.
	ConfigFileName = "config"
	// SiteFileName is the name of the passgo password store file.
	SiteFileName = "sites.json"
	// EncryptedFileDir is the name of the passgo encrypted file dir.
	EncryptedFileDir = "files"
)

var (
	// MasterPassPrompt is the standard prompt string for all passgo
	MasterPassPrompt = "Enter master password"
)

// PassFile is an interface for how all passgo files should be saved.
type PassFile interface {
	SaveFile() (err error)
}

// ConfigFile represents the passgo config file.
type ConfigFile struct {
	MasterKeyPrivSealed []byte
	PubKeyHmac          []byte
	SiteHmac            []byte
	MasterPubKey        [32]byte
	MasterPassKeySalt   [32]byte
	HmacSalt            [32]byte
	SiteHmacSalt        [32]byte
}

// SiteInfo represents a single saved password entry.
type SiteInfo struct {
	PubKey     [32]byte
	PassSealed []byte
	Name       string
	FileName   string
	IsFile     bool
}

// SiteFile represents the entire passgo password store.
type SiteFile []SiteInfo

func PassFileDirExists() (bool, error) {
	d, err := GetEncryptedFilesDir()
	if err != nil {
		return false, err
	}
	dirInfo, err := os.Stat(d)
	if err == nil {
		if dirInfo.IsDir() {
			return true, nil
		}
	} else {
		if os.IsNotExist(err) {
			return false, nil
		}
	}
	return false, err
}

// PassDirExists is used to determine if the passgo
// directory in the user's home directory exists.
func PassDirExists() (bool, error) {
	d, err := GetPassDir()
	if err != nil {
		return false, err
	}
	dirInfo, err := os.Stat(d)
	if err == nil {
		if !dirInfo.IsDir() {
			return true, nil
		}
	} else {
		if os.IsNotExist(err) {
			return false, nil
		}
	}
	return false, err
}

// PassConfigExists is used to determine if the passgo config
// file exists in the user's passgo directory.
func PassConfigExists() (bool, error) {
	c, err := GetConfigPath()
	if err != nil {
		return false, err
	}
	_, err = os.Stat(c)
	if err != nil {
		return false, err
	}
	return true, nil
}

// SitesVaultExists is used to determine if the password store
// exists in the user's passgo directory.
func SitesVaultExists() (bool, error) {
	c, err := GetConfigPath()
	if err != nil {
		return false, err
	}
	sitesFilePath := filepath.Join(c, SiteFileName)
	_, err = os.Stat(sitesFilePath)
	if err != nil {
		return false, err
	}
	return true, nil
}

func GetHomeDir() (d string, err error) {
	usr, err := user.Current()
	if err == nil {
		d = usr.HomeDir
	}
	return
}

// GetPassDir is used to return the user's passgo directory.
func GetPassDir() (d string, err error) {
	d, ok := os.LookupEnv(PASSGODIR)
	if !ok {
		home, err := GetHomeDir()
		if err == nil {
			d = filepath.Join(home, ".passgo")
		}
	}
	return
}

// GetConfigPath is used to get the user's passgo directory.
func GetConfigPath() (p string, err error) {
	d, err := GetPassDir()
	if err == nil {
		p = filepath.Join(d, ConfigFileName)
	}
	return
}

// GetEncryptedFilesDir is used to get the directory that we store
// encrypted files in.
func GetEncryptedFilesDir() (p string, err error) {
	d, err := GetPassDir()
	if err == nil {
		p = filepath.Join(d, EncryptedFileDir)
	}
	return
}

// GetSitesFile will return the user's passgo vault.
func GetSitesFile() (d string, err error) {
	p, err := GetPassDir()
	if err == nil {
		d = filepath.Join(p, SiteFileName)
	}
	return
}

func (s *SiteInfo) AddFile(fileBytes []byte, filename string) error {
	encFileDir, err := GetEncryptedFilesDir()
	if err != nil {
		return err
	}
	// Make sure that the file directory exists.
	fileDirExists, err := PassFileDirExists()
	if err != nil {
		return err
	}
	if !fileDirExists {
		err = os.Mkdir(encFileDir, 0700)
		if err != nil {
			log.Fatalf("Could not create passgo encrypted file dir: %s", err.Error())
		}
	}
	encFilePath := filepath.Join(encFileDir, filename)
	dir, _ := filepath.Split(encFilePath)
	err = os.MkdirAll(dir, 0700)
	if err != nil {
		log.Fatalf("Could not create subdirectory: %s", err.Error())
	}
	err = ioutil.WriteFile(encFilePath, fileBytes, 0666)
	if err != nil {
		return err
	}

	// We still need to add this site info to the bytes.
	return s.AddSite()
}

// AddSite is used by individual password entries to update the vault.
func (s *SiteInfo) AddSite() (err error) {
	siteFile := GetVault()
	for _, si := range siteFile {
		if s.Name == si.Name {
			return errors.New("Could not add site with duplicate name")
		}
	}
	siteFile = append(siteFile, *s)
	return UpdateVault(siteFile)
}

// GetVault is used to retrieve the password vault for the user.
func GetVault() (s SiteFile) {
	si, err := GetSitesFile()
	if err != nil {
		log.Fatalf("Could not get pass dir: %s", err.Error())
	}
	siteFileContents, err := ioutil.ReadFile(si)
	if err != nil {
		if os.IsNotExist(err) {
			log.Fatalf("Could not open site file. Run passgo init.: %s", err.Error())
		}
		log.Fatalf("Could not read site file: %s", err.Error())
	}
	err = json.Unmarshal(siteFileContents, &s)
	if err != nil {
		log.Fatalf("Could not unmarshal site info: %s", err.Error())
	}
	return
}

// GetSiteFileBytes returns the bytes instead of a SiteFile
func GetSiteFileBytes() (b []byte) {
	si, err := GetSitesFile()
	if err != nil {
		log.Fatalf("Could not get pass dir: %s", err.Error())
	}
	f, err := os.OpenFile(si, os.O_RDWR, 0600)
	if err != nil {
		log.Fatalf("Could not open site file: %s", err.Error())
	}
	defer f.Close()
	b, err = ioutil.ReadAll(f)
	if err != nil {
		log.Fatalf("Could not read site file: %s", err.Error())
	}
	return
}

// UpdateVault is used to replace the current password vault.
func UpdateVault(s SiteFile) (err error) {
	si, err := GetSitesFile()
	if err != nil {
		log.Fatalf("Could not get pass dir: %s", err.Error())
	}
	siteFileContents, err := json.MarshalIndent(s, "", "\t")
	if err != nil {
		log.Fatalf("Could not marshal site info: %s", err.Error())
	}

	// Write the site with the newly appended site to the file.
	err = ioutil.WriteFile(si, siteFileContents, 0666)
	return
}

// SaveFile is used by ConfigFiles to update the passgo config.
func (c *ConfigFile) SaveFile() (err error) {
	if exists, err := PassConfigExists(); err != nil {
		log.Fatalf("Could not find config file: %s", err.Error())
	} else {
		if !exists {
			log.Fatalf("pass config could not be found: %s", err.Error())
		}
	}
	cBytes, err := json.MarshalIndent(c, "", "\t")
	if err != nil {
		log.Fatalf("Could not marshal config file: %s", err.Error())
	}
	path, err := GetConfigPath()
	if err != nil {
		log.Fatalf("Could not get config file path: %s", err.Error())
	}
	err = ioutil.WriteFile(path, cBytes, 0666)
	return
}

// ReadConfig is used to return the passgo ConfigFile.
func ReadConfig() (c ConfigFile, err error) {
	config, err := GetConfigPath()
	if err != nil {
		return
	}
	configBytes, err := ioutil.ReadFile(config)
	if err != nil {
		return
	}
	err = json.Unmarshal(configBytes, &c)
	return
}

// GetPassFromFile will get users password from ~/.config/passgo/passgo.pass if present.
func GetPassFromFile() (pass string, err error) {
	passwordFile := os.Getenv("HOME") + "/.config/passgo/passgo.pass"
	content, err := ioutil.ReadFile(passwordFile)
	if err != nil {
		return "", err
	} else {
		fmt.Fprintf(os.Stderr, "Found and using password file, %s\n", passwordFile)
		return strings.TrimSuffix(string(content), "\n"), nil
	}
}

// PromptPass will prompt user's for a password by terminal.
func PromptPass(prompt string) (pass string, err error) {
	// Make a copy of STDIN's state to restore afterward
	fd := int(os.Stdin.Fd())
	oldState, err := terminal.GetState(fd)
	if err != nil {
		panic("Could not get state of terminal: " + err.Error())
	}
	defer terminal.Restore(fd, oldState)

	// Restore STDIN in the event of a signal interuption
	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, os.Interrupt)
	go func() {
		for _ = range sigch {
			terminal.Restore(fd, oldState)
			os.Exit(1)
		}
	}()

	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	passBytes, err := terminal.ReadPassword(fd)
	fmt.Fprintln(os.Stderr, "")
	return string(passBytes), err
}

// Prompt will prompt a user for regular data from stdin.
func Prompt(prompt string) (s string, err error) {
	fmt.Printf("%s", prompt)
	stdin := bufio.NewReader(os.Stdin)
	l, _, err := stdin.ReadLine()
	return string(l), err
}

func ToClipboard(s string) {
	if err := clipboard.WriteAll(s); err != nil {
		log.Fatalf("Could not copy password to clipboard: %s", err.Error())
	}
}
