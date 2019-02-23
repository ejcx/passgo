package main

import (
	"fmt"
	"strconv"

	"github.com/ejcx/passgo/edit"
	"github.com/ejcx/passgo/generate"
	"github.com/ejcx/passgo/initialize"
	"github.com/ejcx/passgo/insert"
	"github.com/ejcx/passgo/pio"
	"github.com/ejcx/passgo/show"
	"github.com/spf13/cobra"
)

const (
	version = `v2.0`
)

var (
	copyPass bool
	RootCmd  = &cobra.Command{
		Use:   "passgo",
		Short: "Print the contents of the vault.",
		Long: `Print the contents of the vault. If you have
not yet initialized your vault, it is necessary to run
the init subcommand in order to create your passgo
directory, and initialize your cryptographic keys.`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(pio.PassFileDirExists())
			if exists, _ := pio.PassFileDirExists(); exists {
				show.ListAll()
			} else {
				cmd.Help()
			}
		},
	}
	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print the version of your passgo binary.",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(version)
		},
	}
	initCmd = &cobra.Command{
		Use:   "init",
		Long:  "Initialize the .passgo directory, and generate your secret keys",
		Args:  cobra.NoArgs,
		Short: "Initialize your passgo vault",
		Run: func(cmd *cobra.Command, args []string) {
			initialize.Init()
		},
	}
	insertCmd = &cobra.Command{
		Use:   "insert",
		Short: "Initialize your passgo vault",
		Args:  cobra.ExactArgs(1),
		Long: `Add a site to your password store. This site can optionally be a part
		of a group by prepending a group name and slash to the site name.
		Will prompt for confirmation when a site path is not unique.`,
		Run: func(cmd *cobra.Command, args []string) {
			pathName := args[0]
			insert.Password(pathName)
		},
	}
	showCmd = &cobra.Command{
		Use:   "show",
		Short: "Print the password of a passgo entry.",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			path := args[0]
			show.Site(path, copyPass)
		},
	}
	generateCmd = &cobra.Command{
		Use:   "generate",
		Short: "Generate a secure password",
		Long: `Prints a randomly generated password. The length of this password defaults
to 24. If a password length is specified as greater than 2048 then generate
will fail.`,
		Args: cobra.RangeArgs(0, 1),
		Run: func(cmd *cobra.Command, args []string) {
			pwlen := -1
			if len(args) != 0 {
				pwlenStr := args[0]
				pwlenint, err := strconv.Atoi(pwlenStr)
				if err != nil {
					pwlen = -1
				} else {
					pwlen = pwlenint
				}
			}
			pass := generate.Generate(pwlen)
			fmt.Println(pass)
		},
	}
	findCmd = &cobra.Command{
		Use:     "find",
		Aliases: []string{"ls"},
		Short:   "Find a site that contains the site-path.",
		Long: `Prints all sites that contain the site-path. Used to print just
one group or all sites that contain a certain word in the group or name`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			path := args[0]
			show.Find(path)
		},
	}
	renameCmd = &cobra.Command{
		Use:   "rename",
		Short: "Rename an entry in the password vault",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			path := args[0]
			edit.Rename(path)
		},
	}
	editCmd = &cobra.Command{
		Use:   "edit",
		Short: "Change the password of a site in the vault.",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			path := args[0]
			edit.Edit(path)
		},
	}
	removeCmd = &cobra.Command{
		Use:     "remove",
		Aliases: []string{"rm"},
		Short:   "Remove a site from the password vault by specifying the entire site-path.",
		Args:    cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			path := args[0]
			edit.RemovePassword(path)
		},
	}
	removeFileCmd = &cobra.Command{
		Use:     "remove-file",
		Aliases: []string{"rm-file", "removefile", "rmfile"},
		Short:   "Remove a file from the vault by specifying the entire file-path.",
		Args:    cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			path := args[0]
			edit.RemoveFile(path)
		},
	}
	insertFileCmd = &cobra.Command{
		Use:     "insert-file",
		Aliases: []string{"insertfile"},
		Short:   "Insert a file in to your vault",
		Args:    cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			path := args[0]
			filename := args[1]
			insert.File(path, filename)
		},
	}
)

func init() {
	showCmd.PersistentFlags().BoolVarP(&copyPass, "copy", "c", false, "Copy your password to the clipboard")
	RootCmd.AddCommand(findCmd)
	RootCmd.AddCommand(generateCmd)
	RootCmd.AddCommand(initCmd)
	RootCmd.AddCommand(insertCmd)
	RootCmd.AddCommand(insertFileCmd)
	RootCmd.AddCommand(removeCmd)
	RootCmd.AddCommand(removeFileCmd)
	RootCmd.AddCommand(renameCmd)
	RootCmd.AddCommand(showCmd)
	RootCmd.AddCommand(versionCmd)
}

func main() {
	RootCmd.Execute()
}
