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
	"github.com/ejcx/passgo/pcsv"
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
= passgo: v1.0                       =
= The simple golang password and     =
= file manager                       =
=                                    =
= Twiinsen Security                  =
= evan@twiinsen.com                  =
= https://twiinsen.com/passgo        =
======================================`
	usage = `Usage:
	passgo
		Print the contents of the vault.
	passgo show site-path
		Print the password of a passgo entry.
	passgo init
		Initialize the .passgo directory, and generate your secret keys.
	passgo import csv-file
		Import a csv file.  The first line must be a comma separated list where
		the columns labeled 'Password' and 'Hostname' (or 'Name') exist.
	passgo insert site-path
		Add a site to your password store. This site can optionally be a part
		of a group by prepending a group name and slash to the site name.
		Will prompt for confirmation when a site path is not unique.
		passgo
	passgo rename site-path
		Rename an entry in the password vault.
	passgo edit site-path
		Change the password of a site in the vault.
	passgo generate length=24
		Prints a randomly generated password. The length of this password defaults
		to 24. If a very short length is specified, the generated password will be
		longer than desired and will contain a upper-case, lower-case, symbol, and
		digit.
	passgo find site-path
		Prints all sites that contain the site-path. Used to print just one group
		or all sites that contain a certain word in the group or name.
	passgo ls site-path
		An alias for the find subcommand.
	passgo remove site-path
		Remove a site from the password vault by specifying the entire site-path.
	passgo removefile site-path
		Remove a file from the vault by specifying the entire file-path.
	passgo rm site-path
		An alias for remove.
	passgo rmfile site-path
		An alias for removefile.
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

func SubArgs(args []string) (subArgs []string, multiline bool) {
	subArgs = args[1:]
	for jj, arg := range subArgs {
		if arg == "-m" || arg == "--multi" {
			multiline = true
			subArgs = append(subArgs[:jj], subArgs[jj+1:]...)
			jj--
		}
	}
	return subArgs, multiline
}

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
	subArgs, multiline := SubArgs(flag.Args())
	switch flag.Args()[0] {
	case "import":
		path := getSubArguments(subArgs, ALLARGS)
		pcsv.Import(path)
	case "edit":
		path := getSubArguments(subArgs, ALLARGS)
		edit.Edit(path, multiline)
	case "ls", "find":
		path := getSubArguments(subArgs, ALLARGS)
		show.Find(path)
	case "generate":
		pwlenStr := getSubArguments(subArgs, 0)
		pwlen, err := strconv.Atoi(pwlenStr)
		if err != nil {
			pwlen = -1
		}
		pass := generate.Generate(pwlen)
		fmt.Println(pass)
	case "init":
		initialize.Init()
	case "insert":
		pathName := getSubArguments(subArgs, ALLARGS)
		insert.Password(pathName, multiline)
	case "integrity":
		pc.GetSitesIntegrity()
		sync.Commit(sync.IntegrityCommit)
	case "rm", "remove":
		path := getSubArguments(subArgs, ALLARGS)
		edit.RemovePassword(path)
	case "rename":
		path := getSubArguments(subArgs, ALLARGS)
		edit.Rename(path)
	case "help", "usage":
		printUsage()
	case "version":
		printVersion()
	case "pull":
		sync.Pull()
	case "push":
		sync.Push()
	case "remote":
		remote := getSubArguments(subArgs, 0)
		sync.Remote(remote)
	case "clone":
		repo := getSubArguments(subArgs, 0)
		sync.Clone(repo)
	case "show":
		path := getSubArguments(flag.Args(), 1)
		show.Site(path, *copyPass)
	case "insertfile":
		allArgs := getSubArguments(subArgs, ALLARGS)
		argList := strings.Split(allArgs, " ")
		if len(argList) != 2 {
			printUsage()
			log.Fatalln("Incorrect args.")
		}
		path := argList[0]
		filename := argList[1]
		insert.File(path, filename)
	case "rmfile", "removefile":
		path := getSubArguments(subArgs, ALLARGS)
		edit.RemoveFile(path)
	default:
		log.Fatalf("%s\nInvalid Command %s", usage, os.Args[1])
	}
}

func printUsage() {
	fmt.Println(usage)
}
func printVersion() {
	fmt.Println(version)
}

// getSubArguments requires the list of subarguments and the
// argument number that you want returned. Non existent args
// will return an empty string. A negative arg index will
// return all arguments concatenated as one.
func getSubArguments(args []string, arg int) string {
	if len(args) == 0 {
		return ""
	}
	if arg < 0 {
		return strings.Join(args, " ")
	}
	if len(args) < arg+1 {
		log.Fatalf("Not enough args")
	}
	return args[arg]
}
