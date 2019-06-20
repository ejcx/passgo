# passgo
stores, retrieves, generates, and synchronizes passwords and files securely and is written in Go! It is inspired by https://passwordstore.org but has a few key differences. The most important difference is passgo is not GPG based. Instead it uses a master password to securely store your passwords. It also supports encrypting arbitrary files.

<img style="max-width:400px" src="https://i.imgur.com/hFXVr4t.gif">

passgo is meant to be secure enough that you can publicly post your vault. I've started publishing my passwords [here](https://github.com/ejcx/passwords.git).

## Installation

`passgo` requires Go version 1.11 or later.

```bash
(cd; GO111MODULE=on go install github.com/ejcx/passgo/v2)
```

## Getting started with passgo

Create a vault and specify the directory to store passwords in. You will be prompted for your master password:

```bash
$ passgo init
Please enter a strong master password:
2019/02/23 16:54:31 Created directory to store passwords: ~/.passgo
```

Finally, to learn more you can either read about the commands listed in this README or run:

```bash
passgo help
```

The `--help` argument can be used on any subcommand to describe it and see documentation or examples.

## Configuring passgo
The `PASSGODIR` environment variable specifies the directory that your vault is in.

I store my vault in the default location `~/.passgo`. All subcommands will respect this environment variable, including `init`


## COMMANDS

### Listing Passwords
```
$ passgo
├──money
|  └──mint.com
└──another
   └──another.com
```

This basic command is used to print out the contents of your password vault. It doesn't require you to enter your master password.


### Initializing Vault
```
$ passgo init
```
Init should only be run one time, before running any other command. It is used for generating your master public private keypair.

By default, passgo will create your password vault in the `.passgo` directory within your home directory. You can override this location using the `PASSGODIR` environment variable.



### Inserting a password
```
$ passgo insert money/mint.com
Enter password for money/mint.com: 
```

Inserting a password in to your vault is easy. If you wish to group multiple entries together, it can be accomplished by prepending a group name followed by a slash to the pass-name. 

Here we are adding mint.com to the password store within the money group.


### Inserting a file
```
$ passgo insert money/budget.csv budget.csv
```

Adding a file works almost the same as insert. Instead it has an extra argument. The file that you want to add to your vault is the final argument. 


### Retrieving a password
```
$ passgo show money/mint.com
Enter master password:
dolladollabills$$1
```

Show is used to display a password in standard out.

	
### Rename a password
```
$ passgo rename mney/mint.com
Enter new site name for mney/mint.com: money/mint.com
```

If a password is added with the wrong name it can be updated later. Here we rename our mint.com site after misspelling the group name.


### Updating a password
```
$ passgo edit money/mint.com
Enter new password for money/mint.com:
```

If you want to securely update a password for an already existing site, the edit command is helpful.



### Generating a password
```
$ passgo generate
%L4^!s,Rry!}s:U<QwliL{vQ

$ passgo generate 8
[;K6otS3
```

passgo can also create randomly generated passwords. The default length of passgo generated passwords is 24 characters. This length can be changed by passing an optional length to the generate subcommand.


### Searching the vault
```
 $ passgo find money
 └──money
    └──mint.com

 $ passgo ls money
 └──money
    └──mint.com
```
`find` and `ls` can both be used to search for all sites that contain a particular substring. It's good for printing out groups of sites as well. `passgo ls` is an alias of `passgo find`.


### Deleting a vault entry
```
$ passgo
├──bb
|  └──ff
├──something
|  └──somethingelse.com
└──twiinsen.com
   └──bbbbb

$ passgo remove bb/ff

$ passgo
├──something
|  └──somethingelse.com
└──twiinsen.com
   └──bbbbb
```

remove is used for removing sites from the password vault. `passgo rm` is an alias of `passgo remove`.



### Getting Help
```
$ passgo --help
```

All subcommands support the `--help` flag.


## CRYPTOGRAPHY DETAILS
###### Password Store Initialization.
passgo only uses AEADs for encrypting data. When `passgo init` is run, users are prompted for a master password. A random salt is generated and the master password along with the salt are passed to the Scrypt algorithm to generate a symmetric master key.

A master public/private keypair is generated when `passgo init` is run. The symmetric master password is used to encrypt the master private key, while the master public key is left in plaintext.

###### Generating Passwords.
Password generation takes place in the pc package by using the GeneratePassword function. GeneratePassword creates a random password by reading a large amount of randomness using the `func Read([]byte) (int, error)` function in the `crypto/rand` package.

The block of randomness is then read byte-by-byte. Printable characters that match the desired password specification (uppercase, lowercase, symbols, and digits) are then included in the generated password.

###### Adding A Site.
When a site is added to the password store, a new public private key pair is generated. The newly generated private key, the user's master public key, and a securely generated nonce are used to encrypt the sites data.

The encryption and key computation are done using the `golang.org/x/crypto/nacl/box` package which uses Curve25519, XSalsa20, and Poly1305 to encrypt and authenticate the site's data.

After the site information is added, the site's generated private key is thrown away.

## Threat model
The threat model of passgo assumes there are no attackers on your local machine. The passgo vault puts some level of trust in the remote git repository.

An evil git server could modify the public key of your vault. If the evil git server does this then passgo will tell you that the Vault integrity cannot be verified the next time you attempt to read a password.
