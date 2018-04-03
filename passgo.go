package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/ejcx/passgo/generate"
	"github.com/ejcx/passgo/pc"
	"github.com/ejcx/passgo/sync"
	"github.com/f06ybeast/passgo/edit"
	"github.com/f06ybeast/passgo/initialize"
	"github.com/f06ybeast/passgo/insert"
	"github.com/f06ybeast/passgo/pio"
	"github.com/f06ybeast/passgo/show"
)

const (
	ALLARGS = -1
)

var (
	// copyPass indicates that the shown password should be copied to the clipboard.
	copyPass = flag.Bool("copy", true, "If true, copy password to clipboard instead of displaying it")

	version = `======================================
= passgo v1.04 (f06ybeast mod)       =
= user/pass and file manager         =
= with AEAD/NaCl encryption          =
=                                    =
= evan@twiinsen.com                  =
= https://github.com/ejcx/passgo     =
======================================`
	usage = `Usage:
  passgo
    Print the site and file names of the vault.
  passgo show site-path|file-path
    If site, print the username, and send password to clipboard.
    If file, send file contents to clipboard.
  passgo init
    Initialize the .passgo directory, and generate secret keys.
  passgo insert site-path
    Add a site to password store. This site can optionally be a part
    of a group by prepending a group name and slash to the site name.
    Will prompt for confirmation when a site path is not unique.
  passgo insertfile name file-path
    Adding a file works almost the same as insert. Instead it has an extra 
    argument. The file that you want to add to your vault is the final 
    argument. Grouping works the same way with insertfile as insert.
  passgo rename site-path
    Rename an entry in the password vault.
  passgo edit site-path
    Change the username and password of a site in the vault
  passgo generate|clear [length]
    Prints a randomly generated password. The length of this password defaults
    to 24. If a very short length is specified, the generated password will be
    longer than desired and will contain a upper-case, lower-case, symbol, and
    digit. Pastes to clipboard. On 'clear', it then clears the clipboard.
  passgo find|ls site-path
    Prints all sites that contain the site-path. Used to print just one group
    or all sites that contain a certain word in the group or name.
  passgo remove|rm site-path
    Remove a site from the password vault by specifying the entire site-path.
  passgo removefile|rmfile site-path
    Remove a file from the vault by specifying the entire file-path.
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
  passgo usage|help
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
	switch flag.Args()[0] {
	case "ls", "find":
		path := getSubArguments(subArgs, ALLARGS)
		show.Find(path)
	case "generate", "clear":
		pwlenStr := getSubArguments(subArgs, 0)
		pwlen, err := strconv.Atoi(pwlenStr)
		if err != nil {
			pwlen = -1
		}
		pass := generate.Generate(pwlen)
		if flag.Args()[0] == "clear" {
			pio.ToClipboard(pass)
			pio.ToClipboard("")
			fmt.Println("Clipboard cleared.")
			break
		}
		fmt.Println(pass)
		fmt.Println("\n@ Clipboard")
		pio.ToClipboard(pass)
	case "edit":
		path := getSubArguments(subArgs, ALLARGS)
		edit.Edit(path)
	case "init":
		initialize.Init()
	case "insert":
		pathName := getSubArguments(subArgs, ALLARGS)
		insert.Insert(pathName)
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
