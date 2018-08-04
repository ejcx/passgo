package pcsv

import (
	"bytes"
	"crypto/rand"
	"encoding/csv"
	"encoding/json"
	"io/ioutil"
	"log"
	"strings"

	"github.com/ejcx/passgo/pc"
	"github.com/ejcx/passgo/pio"
	"github.com/ejcx/passgo/sync"
	"golang.org/x/crypto/nacl/box"
)

func Import(path string) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatalf("Failed to read file %s: %s", path, err.Error())
	}
	r := csv.NewReader(bytes.NewReader(b))
	records, err := r.ReadAll()
	if err != nil {
		log.Fatalf("Csv failed to read bytes %s", err.Error())
	}
	nameAt, hostAt, passAt := -1, -1, -1
	columns := []string{}
	for jj, record := range records {
		if jj == 0 {
			for kk, col := range record {
				if strings.ToLower(col) == "password" {
					passAt = kk
				}
				if strings.ToLower(col) == "hostname" {
					hostAt = kk
				}
				if strings.ToLower(col) == "name" {
					nameAt = kk
				}
			}
			if passAt == -1 || (hostAt == -1 && nameAt == -1) {
				log.Fatal("The password and hostname/name columns are required.")
			}
			columns = record
		} else {
			ImportMultiEntry(columns, record, passAt, hostAt, nameAt)
		}
	}
}

func ImportMultiEntry(colNames []string, record []string, passAt, hostAt, nameAt int) {
	var c pio.ConfigFile
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Could not generate site key: %s", err.Error())
	}

	config, err := pio.GetConfigPath()
	if err != nil {
		log.Fatalf("Could not get config file name: %s", err.Error())
	}

	// Read the master public key.
	configContents, err := ioutil.ReadFile(config)
	if err != nil {
		log.Fatalf("Could not get config file contents: %s", err.Error())
	}

	err = json.Unmarshal(configContents, &c)
	if err != nil {
		log.Fatalf("Could not unmarshal config file contents: %s", err.Error())
	}

	masterPub := c.MasterPubKey

	passSealed, err := pc.SealAsym([]byte(record[passAt]), &masterPub, priv)

	var notesSealed [][]byte
	if len(record) > 2 {
		for jj, column := range record {
			if jj != hostAt && jj != passAt {
				noteSealed, err := pc.SealAsym([]byte(colNames[jj]+": "+column), &masterPub, priv)
				if err != nil {
					log.Fatalf("Could not seal note: %s", err.Error())
				}
				notesSealed = append(notesSealed, noteSealed)
			}
		}
	}
	si := pio.SiteInfo{
		PubKey:      *pub,
		Name:        record[hostAt],
		PassSealed:  passSealed,
		NotesSealed: notesSealed,
	}

	err = si.AddSite()
	if err != nil {
		si.Name = record[nameAt]
		err = si.AddSite()
		if err != nil {
			log.Printf("Could not save site file '%s': %s", strings.Join(record, " "), err.Error())
			return
		}
	}
	sync.InsertCommit(record[hostAt])
}
