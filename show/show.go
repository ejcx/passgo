package show

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/f06ybeast/passgo/generate"
	"github.com/f06ybeast/passgo/pc"
	"github.com/f06ybeast/passgo/pio"
)

type searchType int

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

var (
	lastPrefix      = "└──" // [U+2514 U+2500...] "BOX DRAWINGS LIGHT UP AND RIGHT", "...LIGHT HORIZONTAL", ...
	regPrefix       = "├──" // [U+251C U+2500...] "BOX DRAWINGS LIGHT VERTICAL AND RIGHT", ...
	innerPrefix     = "│  " // [U+2502 U+0020...] "BOX DRAWINGS LIGHT VERTICAL", ...
	innerLastPrefix = "   "
)

func init() {
	switch runtime.GOOS {
	case "windows":
		lastPrefix = "+--"
		regPrefix = "+--"
		innerPrefix = "|  "
	}
	switch runtime.GOARCH {
	case "arm", "arm64":
		lastPrefix = "+--"
		regPrefix = "+--"
		innerPrefix = "|  "
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

// Site takes a path, and prompts for master password, then prints site info for that path.
// If path is empty-string, then it loops, prompting for path and returning that site's info,
// allowing access to multiple sites' info without re-entering master password.
func Site(path string, copyPassword bool) {
	if path == "" {
		masterPrivKey := pc.GetMasterKey()
		for {
			path, _ = pio.Prompt("Enter site name")
			if path == "" {
				if copyPassword {
					clearClipboard()
				}
				break
			}
			allSites, allErrors := SearchAll(One, path)
			if len(allSites) == 0 {
				fmt.Printf("Site '%s' not found.\n", path)
				if copyPassword {
					clearClipboard()
				}
			} else {
				showPassword(allSites, masterPrivKey, copyPassword)
				handleErrors(allErrors)
			}
		}
	} else {
		allSites, allErrors := SearchAll(One, path)
		if len(allSites) == 0 {
			fmt.Printf("Site with path %s not found", path)
			return
		}
		masterPrivKey := pc.GetMasterKey()
		showPassword(allSites, masterPrivKey, copyPassword)
		handleErrors(allErrors)
	}
}

func clearClipboard() {
	pio.ToClipboard(generate.Generate(24))
	pio.ToClipboard("")
	fmt.Println("Clipboard cleared.")
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
			var unsealedUser, unsealedPass []byte
			var err error
			if site.IsFile {
				fileDir, err := pio.GetEncryptedFilesDir()
				pio.LogF(err, "Could not get encrypted file dir when searching vault")
				filePath := filepath.Join(fileDir, site.FileName)

				f, err := os.OpenFile(filePath, os.O_RDONLY, 0600)
				pio.LogF(err, "Could not open encrypted file")
				defer f.Close()

				fileSealed, err := ioutil.ReadAll(f)
				pio.LogF(err, "Could not read encrypted file")

				unsealedPass, err = pc.OpenAsym(fileSealed, &site.PubKey, &masterPrivKey)
				pio.LogF(err, "Could not decrypt file bytes")
			} else {
				unsealedUser, err = pc.OpenAsym(site.UserSealed, &site.PubKey, &masterPrivKey)
				pio.LogF(err, "Could not decrypt site username")

				unsealedPass, err = pc.OpenAsym(site.PassSealed, &site.PubKey, &masterPrivKey)
				pio.LogF(err, "Could not decrypt site password")
			}

			fmt.Printf("\n Site: %s\n", string(site.Name))
			fmt.Printf(" User: %s\n", string(unsealedUser))
			if copyPassword {
				fmt.Printf(" %s\n\n", "Pass: @ Clipboard")
				pio.ToClipboard(string(unsealedPass))
			} else {
				fmt.Printf(" Pass: %s\n\n", string(unsealedPass))
			}
		}
	}
}

func showResults(allSites map[string][]pio.SiteInfo) {
	// Go maps don't sort, so extract the map fields into a slice of a struct
	type show struct {
		group string
		names []string
	}
	// sort
	sites := make([]show, 0, 3*len(allSites))
	total := 0
	for group := range allSites {
		names := make([]string, 0, len(allSites[group]))
		for i := range allSites[group] {
			names = append(names, allSites[group][i].Name)
			total++
		}
		if group == "" {
			for _, name := range names {
				sites = append(sites, show{name, []string{name}})
			}
		} else {
			sort.Strings(names)
			sites = append(sites, show{group, names})
		}
	}
	sort.Slice(sites, func(i, j int) bool {
		return strings.ToLower(sites[i].group) < strings.ToLower(sites[j].group)
	})
	// show
	fmt.Printf("  %d\n", total)
	t := `   `
	for i, site := range sites {
		for j, name := range site.names {
			pG := regPrefix
			pN := innerPrefix + regPrefix

			if (j + 1) == len(site.names) {
				pN = innerPrefix + lastPrefix
			}
			if (i + 1) == len(sites) {
				pG = lastPrefix
				if (j + 1) == len(site.names) {
					pN = innerLastPrefix + lastPrefix
				} else {
					pN = innerLastPrefix + regPrefix
				}
			}

			if j == 0 {
				fmt.Printf("%s%s%s\n", t, pG, site.group)
			}
			if site.group != name {
				fmt.Printf("%s%s%s\n", t, pN, name)
			}
		}
	}
}

// SearchAll will perform a search of searchType with optionally used searchFor. It
// will return all sites as a map of group names to pio.SiteInfo types. That way, callers
// of this function do not need to sort the sites by group themselves.
func SearchAll(st searchType, searchFor string) (allSites map[string][]pio.SiteInfo, allErrors []error) {
	allSites = map[string][]pio.SiteInfo{}
	siteFile, err := pio.GetSitesFile()
	pio.LogF(err, "Could not get site file")

	siteFileContents, err := ioutil.ReadFile(siteFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Fatalf("Could not open site file. Run passgo init.: %s", err.Error())
		}
		log.Fatalf("Could not read site file contents: %s", err.Error())
	}

	var sites pio.SiteFile
	err = json.Unmarshal(siteFileContents, &sites)
	pio.LogF(err, "Could not unmarshal site file contents")

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
