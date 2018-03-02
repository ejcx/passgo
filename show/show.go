package show

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/f06ybeast/passgo/pc"
	"github.com/f06ybeast/passgo/pio"
)

type searchType int

var (
	lastPrefix      = "└──"
	regPrefix       = "├──"
	innerPrefix     = "|  "
	innerLastPrefix = "   "
)

const (
	// All indicates SearchSites should return all sites from the vault.
	All searchType = iota
	// One indicates SearchSites should return only one site from the vault.
	// It is used when printing a site.
	One
	// Search indicates that SearchSites should return all sites found that
	// match that contain the searchFor string
	Search
)

func init() {
	/* Windows doesn't work with ambiguous width characters */
	if runtime.GOOS == "windows" {
		lastPrefix = "+--"
		regPrefix = "+--"
	}
}

func handleErrors(allErrors []error) {
	errorStr := "Error"
	if len(allErrors) == 0 {
		return
	} else if len(allErrors) > 1 {
		errorStr = "Errors"
	}
	log.Printf("%d %s encountered:\n", len(allErrors), errorStr)
	for n, err := range allErrors {
		log.Printf("Error %d: %s", n, err.Error())
	}
}

// Find will search the vault for all occurences of frag in the site name.
func Find(frag string) {
	allSites, allErrors := SearchAll(Search, frag)
	showResults(allSites)
	handleErrors(allErrors)
}

// Site will print out the password of the site that matches path
func Site(path string, copyPassword bool) {
	allSites, allErrors := SearchAll(One, path)
	if len(allSites) == 0 {
		fmt.Printf("Site with path %s not found", path)
		return
	}
	masterPrivKey := pc.GetMasterKey()
	showPassword(allSites, masterPrivKey, copyPassword)
	handleErrors(allErrors)
}

// ListAll will print out all contents of the vault.
func ListAll() {
	allSites, allErrors := SearchAll(All, "")
	showResults(allSites)
	handleErrors(allErrors)
}

func showPassword(allSites map[string][]pio.SiteInfo, masterPrivKey [32]byte, copyPassword bool) {
	for _, siteList := range allSites {
		for _, site := range siteList {
			var unsealedUser []byte
			var unsealedPass []byte
			var err error
			if site.IsFile {
				fileDir, err := pio.GetEncryptedFilesDir()
				if err != nil {
					log.Fatalf("Could not get encrypted file dir when searching vault: %s", err.Error())
				}
				filePath := filepath.Join(fileDir, site.FileName)
				f, err := os.OpenFile(filePath, os.O_RDONLY, 0600)
				if err != nil {
					log.Fatalf("Could not open encrypted file: %s", err.Error())
				}
				defer f.Close()

				fileSealed, err := ioutil.ReadAll(f)
				if err != nil {
					log.Fatalf("Could not read encrypted file: %s", err.Error())
				}
				unsealedPass, err = pc.OpenAsym(fileSealed, &site.PubKey, &masterPrivKey)
				if err != nil {
					log.Fatalf("Could not decrypt file bytes: %s", err.Error())
				}
			} else {
				unsealedUser, err = pc.OpenAsym(site.UserSealed, &site.PubKey, &masterPrivKey)
				if err != nil {
					log.Println("Could not decrypt site USERNAME.")
					//log.Fatalf("FAILed @ unsealedUser :: %v", site.UserSealed)
					continue
				}
				unsealedPass, err = pc.OpenAsym(site.PassSealed, &site.PubKey, &masterPrivKey)
				if err != nil {
					log.Println("Could not decrypt site PASSWORD.")
					//log.Fatalf("FAILed @ unsealedPass :: %v", site.PassSealed)
					continue
				}
			}
			fmt.Printf(" Site: %s", string(site))
			fmt.Printf(" User: %s", string(unsealedUser))
			if copyPassword {
				pio.ToClipboard(string(unsealedPass))
			} else {
				fmt.Println(string(unsealedPass))
			}
		}
	}
}

func showResults(allSites map[string][]pio.SiteInfo) {
	fmt.Println(".")
	counter := 1
	for group, siteList := range allSites {
		siteCounter := 1
		for _, site := range siteList {
			preGroup := regPrefix
			preName := innerPrefix + regPrefix
			if counter == len(allSites) {
				preGroup = lastPrefix
				sitePrefix := innerLastPrefix
				if group == "" {
					sitePrefix = ""
				}
				preName = sitePrefix + regPrefix
				if siteCounter == len(siteList) {
					preName = sitePrefix + lastPrefix
				}
			} else {
				if siteCounter == len(siteList) {
					preName = innerPrefix + lastPrefix
				}
			}

			if siteCounter == 1 {
				if group != "" {
					fmt.Println(preGroup + group)
				}
			}
			fmt.Printf("%s%s\n", preName, site.Name)
			siteCounter++
		}
		counter++
	}
}

// SearchAll will perform a search of searchType with optionally used searchFor. It
// will return all sites as a map of group names to pio.SiteInfo types. That way, callers
// of this function do not need to sort the sites by group themselves.
func SearchAll(st searchType, searchFor string) (allSites map[string][]pio.SiteInfo, allErrors []error) {
	allSites = map[string][]pio.SiteInfo{}
	siteFile, err := pio.GetSitesFile()
	if err != nil {
		log.Fatalf("Could not get site file: %s", err.Error())
	}

	siteFileContents, err := ioutil.ReadFile(siteFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Fatalf("Could not open site file. Run passgo init.: %s", err.Error())
		}
		log.Fatalf("Could not read site file contents: %s", err.Error())
	}

	var sites pio.SiteFile
	err = json.Unmarshal(siteFileContents, &sites)
	if err != nil {
		log.Fatalf("Could not unmarshal site file contents: %s", err.Error())
	}

	for _, s := range sites {
		slashIndex := strings.Index(string(s.Name), "/")
		group := ""
		if slashIndex > 0 {
			group = string(s.Name[:slashIndex])
		}
		name := s.Name[slashIndex+1:]
		user := s.UserSealed
		pass := s.PassSealed
		pubKey := s.PubKey
		isFile := s.IsFile
		filename := s.FileName
		si := pio.SiteInfo{
			Name:       name,
			UserSealed: user,
			PassSealed: pass,
			PubKey:     pubKey,
			IsFile:     isFile,
			FileName:   filename,
		}
		if st == One {
			if name == searchFor || fmt.Sprintf("%s/%s", group, name) == searchFor {
				return map[string][]pio.SiteInfo{
					group: []pio.SiteInfo{
						si,
					},
				}, allErrors
			}
		} else if st == All {
			if allSites[group] == nil {
				allSites[group] = []pio.SiteInfo{}
			}
			allSites[group] = append(allSites[group], si)
		} else if st == Search {
			if strings.Contains(group, searchFor) || strings.Contains(name, searchFor) {
				if allSites[group] == nil {
					allSites[group] = []pio.SiteInfo{}
				}
				allSites[group] = append(allSites[group], si)
			}
		}
	}
	return
}
