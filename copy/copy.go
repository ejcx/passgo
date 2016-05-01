package copy

import (
  "fmt"
  "log"

  "github.com/atotto/clipboard"
  "github.com/ejcx/passgo/show"
  "github.com/ejcx/passgo/pc"
  "github.com/ejcx/passgo/pio"
)

// This function copies the password for a site to the clipboard.
// Operating systems works differently, as an example: to copy
// to the clipboard on a unix system, the user must first install
// xsel or xclip
func Copy(site string) {
  allSites, _ := show.SearchAll(show.One, site)
  if len(allSites) == 0 {
    fmt.Printf("Site with path %s not found\n", site)
    return
  } else if len(allSites) > 1 {
    fmt.Printf("Can only copy one site's password to clipboard")
    return
  }
  masterPrivKey := pc.GetMasterKey()
  copyPassword(allSites, masterPrivKey)
}

func copyPassword(allSites map[string][]pio.SiteInfo, masterPrivKey [32]byte) {
	for _, siteList := range allSites {
		for _, site := range siteList {
			sitePassword, err := pc.OpenAsym(site.PassSealed, &site.PubKey, &masterPrivKey)
			if err != nil {
				log.Println("Could not decrypt site password.")
				continue
			}
      toClipboard(string(sitePassword))
		}
	}
}

func toClipboard(password string) {
  if err := clipboard.WriteAll(string(password)); err != nil {
    fmt.Println(err)
    return
  }
  fmt.Println("Password successfully copied to clipboard")
}
