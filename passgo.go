package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"flag"

	"github.com/ejcx/passgo/edit"
	"github.com/ejcx/passgo/generate"
	"github.com/ejcx/passgo/initialize"
	"github.com/ejcx/passgo/insert"
	"github.com/ejcx/passgo/pio"
	"github.com/ejcx/passgo/show"
	"github.com/ejcx/passgo/sync"
	"github.com/ejcx/passgo/copy"
)

var (
	version = `======================================
= passgo: v0.0                       =
= The simple golang password manager =
=                                    =
= Twiinsen Security                  =
= evan@twiinsen.com                  =
= https://twiinsen.com/passgo        =
======================================`
	usage = `Usage:
	passgo
		Print the contents of the vault.
	passgo init
		Initialize the .passgo directory, and generate your secret keys.
	passgo insert site-path
		Add a site to your password store. This site can optionally be a part
		of a group by prepending a group name and slash to the site name.
		Will prompt for confirmation when a site path is not unique.
		passgo
	passgo rename site-path
		Rename an entry in the password vault.
	passgo edit site-path
		Change the password of a site in the vault.
	passgo generate
		Prints a randomly generated password. The length of this
	passgo find site-path
		Prints all sites that contain the site-path. Used to print just one group
		or all sites that contain a certain word in the group or name.
	passgo ls site-path
		An alias for the find subcommand.
	passgo remove site-path
		Remove a site from the password vault by specifying the entire site-path.
	passgo rm site-path
		An alias for remove.
	passgo pull
		Pull will perform a git pull and sync the changes in the remote git
		repository with your local repo.
	passgo push
		Push will perform a git push to sync your changes with your remote
		git repository.
	passgo remote remote-url
		Remote is used to set the remote repository url. This is the repository
		that your sites will be pushed to and pulled from.
	passgo clone remote-url
		Clone will copy the remote url in to the .passgo directory in your
		home directory. It will fail if the directory already exists.
	passgo usage
		Print this message!
	passgo version
		Print version information
`
)

var copyPass = flag.Bool("copy", false, "If true, copy password to clipboard instead of displaying it")

func main() {
	flag.Parse()
	if len(os.Args) < 2 {
		show.ListAll()
		return
	}

	// Check to see if this user is under attack.
	pio.CheckAttackFile()

	// Handle passgo subcommands.
	switch os.Args[1] {
	case "edit":
		if enoughArguments(2) {
			addArgList := os.Args[2:]
			path := strings.Join(addArgList, " ")
			edit.Edit(path)
		}
	case "ls":
		fallthrough
	case "find":
		addArgList := os.Args[2:]
		path := strings.Join(addArgList, " ")
		show.Find(path)
	case "generate":
		if enoughArguments(2) {
			pwlenStr := os.Args[2]
			pwlen, err := strconv.Atoi(pwlenStr)
			if err != nil {
				pwlen = -1
			}
			pass := generate.Generate(pwlen)
			fmt.Println(pass)
		}
	case "init":
		initialize.Init()
	case "insert":
		if enoughArguments(2) {
			addArgList := os.Args[2:]
			pathName := strings.Join(addArgList, " ")
			insert.Insert(pathName)
		}
	case "rm":
		fallthrough
	case "remove":
		if enoughArguments(2) {
			addArgList := os.Args[2:]
			path := strings.Join(addArgList, " ")
			edit.Remove(path)
		}
	case "rename":
		if enoughArguments(2) {
			addArgList := os.Args[2:]
			path := strings.Join(addArgList, " ")
			edit.Rename(path)
		}
	case "help":
		fallthrough
	case "usage":
		fmt.Println(usage)
	case "version":
		fmt.Println(version)
	// These are used for syncing passwords.
	case "pull":
		sync.Pull()
	case "push":
		sync.Push()
	case "remote":
		if enoughArguments(2) {
			remote := os.Args[2]
			sync.Remote(remote)
		}
	case "clone":
		if enoughArguments(2) {
			repo := os.Args[2]
			sync.Clone(repo)
		}
	default:
		if *copyPass {
			path := os.Args[2]
			copy.Copy(path)
		} else {
			addArgList := os.Args[1:]
			path := strings.Join(addArgList, " ")
			show.Site(path)
		}
	}
}

func enoughArguments(argumentIndex int) bool {
	if len(os.Args) < argumentIndex + 1 {
		fmt.Println("Not enough arguments, use 'gopass usage' for help")
		return false
	}
	return true
}
