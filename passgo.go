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
		path := getArguments(2, false, true)
		edit.Edit(path)
	case "ls":
		fallthrough
	case "find":
		path := getArguments(2, false, false)
		show.Find(path)
	case "generate":
		pwlenStr := getArguments(2, true, false)
		pwlen, err := strconv.Atoi(pwlenStr)
		if err != nil {
			pwlen = -1
		}
		pass := generate.Generate(pwlen)
		fmt.Println(pass)
	case "init":
		initialize.Init()
	case "insert":
		pathName := getArguments(2, false, true)
		insert.Insert(pathName)
	case "rm":
		fallthrough
	case "remove":
		path := getArguments(2, false, true)
		edit.Remove(path)
	case "rename":
		path := getArguments(2, false, true)
		edit.Rename(path)
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
		remote := getArguments(2, true, true)
		sync.Remote(remote)
	case "clone":
		repo := getArguments(2, true, true)
		sync.Clone(repo)
	default:
		if *copyPass {
			path := getArguments(2, true, true)
			copy.Copy(path)
		} else {
			path := getArguments(1, true, true)
			show.Site(path)
		}
	}
}

// A helper function for getting arguments from the user. The 'startIndex' paramter
// is used for telling where the first argument is expected to be. The 'exact'
// paramter is used to determine if only the first found argument should be
// returned or if all arguments should be returned as a string split by spaces.
// The 'required' paramter determines if the argument is needed to continue. If
// 'required' is set to true and no paramter can be found an error message is
// printed and the program exits.
func getArguments(startIndex int, exact bool, required bool) string {
	if len(os.Args) < startIndex + 1 {
		if required {
			fmt.Println("Not enough arguments, use 'gopass usage' for help")
			os.Exit(1)
		} else {
			return ""
		}
	}

	if exact {
		return os.Args[startIndex]
	} else {
		return strings.Join(os.Args[startIndex:], " ")
	}
}
