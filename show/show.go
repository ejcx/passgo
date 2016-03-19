package show

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/ejcx/passgo/pc"
	"github.com/ejcx/passgo/pio"
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
func Site(path string) {
	allSites, allErrors := SearchAll(One, path)
	if len(allSites) == 0 {
		fmt.Printf("Site with path %s not found", path)
		return
	}
	masterPrivKey := pc.GetMasterKey()
	showPassword(allSites, masterPrivKey)
	handleErrors(allErrors)
}

// ListAll will print out all contents of the vault.
func ListAll() {
	allSites, allErrors := SearchAll(All, "")
	showResults(allSites)
	handleErrors(allErrors)
}

func showPassword(allSites map[string][]pio.SiteInfo, masterPrivKey [32]byte) {
	for _, siteList := range allSites {
		for _, site := range siteList {
			sitePassword, err := pc.OpenAsym(site.PassSealed, &site.PubKey, &masterPrivKey)
			if err != nil {
				log.Println("Could not decrypt site password.")
				continue
			}
			fmt.Println(string(sitePassword))
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
				preName = innerLastPrefix + regPrefix
				if siteCounter == len(siteList) {
					preName = innerLastPrefix + lastPrefix
				}
			} else {
				if siteCounter == len(siteList) {
					preName = innerPrefix + lastPrefix
				}
			}

			if siteCounter == 1 {
				fmt.Println(preGroup + group)
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

	f, err := os.Open(siteFile)
	if err != nil {
		log.Fatalf("Could not open site file: %s", err.Error())
	}

	siteFileContents, err := ioutil.ReadAll(f)
	if err != nil {
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
		pass := s.PassSealed
		pubKey := s.PubKey
		si := pio.SiteInfo{
			Name:       name,
			PassSealed: pass,
			PubKey:     pubKey,
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
