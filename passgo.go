package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/ejcx/passgo/edit"
	"github.com/ejcx/passgo/generate"
	"github.com/ejcx/passgo/initialize"
	"github.com/ejcx/passgo/insert"
	"github.com/ejcx/passgo/pc"
	"github.com/ejcx/passgo/pio"
	"github.com/ejcx/passgo/show"
	"github.com/ejcx/passgo/sync"
)

const (
	ALLARGS = -1
)

var (
	// copyPass indicates that the shown password should be copied to the clipboard.
	copyPass = flag.Bool("copy", false, "If true, copy password to clipboard instead of displaying it")

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
	passgo integrity
		Update the integrity hash of your password store if you are planning
		to manually push to the server.
	passgo usage
		Print this message!
	passgo version
		Print version information
`
)

func main() {
	// Check to see if this user is under attack.
	pio.CheckAttackFile()

	flag.Parse()

	// Default behavior of just running the command is listing all sites.
	if len(flag.Args()) < 1 {
		show.ListAll()
		return
	}

	// subArgs is used by subcommands to retreive only their args.
	subArgs := flag.Args()[1:]

	switch os.Args[1] {
	// Handle passgo subcommands.
	case "edit":
		path := getSubArguments(subArgs, 0, true)
		edit.Edit(path)
	case "ls":
		fallthrough
	case "find":
		path := getSubArguments(subArgs, 0, false)
		show.Find(path)
	case "generate":
		pwlenStr := getSubArguments(subArgs, 0, false)
		pwlen, err := strconv.Atoi(pwlenStr)
		if err != nil {
			pwlen = -1
		}
		pass := generate.Generate(pwlen)
		fmt.Println(pass)
	case "init":
		initialize.Init()
	case "insert":
		pathName := getSubArguments(subArgs, 0, true)
		insert.Insert(pathName)
	case "integrity":
		pc.GetSitesIntegrity()
		sync.Commit(sync.IntegrityCommit)
	case "rm":
		fallthrough
	case "remove":
		path := getSubArguments(subArgs, 0, true)
		edit.Remove(path)
	case "rename":
		path := getSubArguments(subArgs, 0, true)
		edit.Rename(path)
	case "help":
		fallthrough
	case "usage":
		printUsage()
	case "version":
		fmt.Println(version)
	// These are used for syncing passwords.
	case "pull":
		sync.Pull()
	case "push":
		sync.Push()
	case "remote":
		remote := getSubArguments(subArgs, 0, true)
		sync.Remote(remote)
	case "clone":
		repo := getSubArguments(subArgs, 0, true)
		sync.Clone(repo)
	default:
		path := getSubArguments(flag.Args(), 0, true)
		show.Site(path, *copyPass)
	}
}

func printUsage() {
	fmt.Println(usage)
}
func printVersion() {
	fmt.Println(version)
}

// getSubArguments takes a list of arguments, an argument index and a
// flag indicating wheter an argument is required or not. If an argument
// is required but not specified, an error message will be printed. If
// not required, an empty string will be returned. -1 can be passed as
// argument index to get all arguments concatenated as one.
func getSubArguments(args []string, arg int, required bool) string {
	if required && ((arg < 0 && len(args) == 0) || (arg >= 0 && len(args) < arg + 1)) {
		log.Fatalf("Not enough arguments specified")
	} else if !required && len(args) == 0 {
		return ""
	} else if arg < 0 {
		return strings.Join(args, " ")
	}
	return args[arg]
}
