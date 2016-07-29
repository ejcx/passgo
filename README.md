[![Build Status](https://travis-ci.org/ejcx/passgo.svg?branch=master)](https://travis-ci.org/ejcx/passgo)
# passgo
stores, retrieves, generates, and synchronizes passwords securely and is written in Go! It is inspired by https://passwordstore.org but has a few key differences. The most important difference is passgo is not GPG based. Instead it uses a master password to securely store your passwords.

passgo is meant to be secure enough that you can publicly post your password vault. I've started publishing my passwords [here](https://github.com/ejcx/passwords.git).

## Getting started with passgo

First make sure you have [installed golang](https://golang.org/doc/install) and set up your [`$GOPATH`](https://github.com/golang/go/wiki/GOPATH).

It's recommend that you add `$GOPATH/bin` to your `$PATH`. This will make any golang executables available as commands in bash for you to use. Add the following to `~/.bashrc` and restart your terminal:

```bash
export PATH=$PATH:$GOPATH/bin
```

Then you can download gopass, its dependencies and install them all with one command:

```bash
go get github.com/ejcx/passgo
```

Next create a vault to store passwords in and a master password:

```bash
passgo init
```

Finally, to learn more you can either read about the commands listed in this README or run:

```bash
passgo usage
```

## COMMANDS

#### passgo
This basic command is used to print out the contents of your password vault. It doesn't require you to enter your master password.

```
$ passgo
├──mney
|  └──mint.com
└──anothergroup
   └──another.com
```


#### passgo init
Init should only be run one time, before running any other command. It is used for generating your master public private keypair.

```
$ passgo init
```

#### passgo insert group/pass-name
Adding a site is easy. If you wish to group multiple entries together, it can be accomplished by prepending a group name followed by a slash to the pass-name. Here we are adding mint.com to the password store.

```
$ passgo insert mint.com
```

Here we are adding mint.com to the password store, but more specifically to the money group. Now, mint.com will be grouped with other sites in the money group.

```
$ passgo insert mney/mint.com
```

#### passgo show group/pass-name
Show is used to display a password in standard out. *Previously it was possible to display a password using `passgo group/pass-name` but this is no longer supported*.

```
$ passgo show mney/mint.com
Enter master password:
dolladollabills$$1
```
	
#### passgo rename group/pass-name
If we add a site and wish to change the name of the site later it is simple to do. Here we rename our mint.com site after misspelling the group name.

```
$ passgo rename mney/mint.com
Enter new site name for mney/mint.com: money/mint.com
```

#### passgo edit group/pass-name
If you want to securely update a password for an already existing site, the edit command is helpful.

```
$ passgo edit money/mint.com
Enter new password for money/mint.com:
```

#### passgo generate
passgo can also create randomly generated passwords. The default length of passgo generated passwords is 24 characters. This length can be changed by passing a length to the generate subcommand.

```
$ passgo generate
%L4^!s,Rry!}s:U<QwliL{vQ
$ passgo generate 123   
q)Z5+%#@7[<dk;r\Kw;`}z2|}GjWJpT;Jn[!~(=T6XjVw4`,X(j}YK,fg;m;R#cs3,b7x`SM!Eb[,1`CSJ\1;>[9m$/N`@nI4Qi#Cl&`LQYy;-Y`qH<gv#t@x`M
```

#### passgo find sub-name
find can be used to search for all sites that contain a particular substring. It's good for printing out groups of sites as well. `passgo ls` is an alias of `passgo find`.
```
 $ passgo find money
 └──money
    └──mint.com
 $ passgo ls money
 └──money
    └──mint.com
```

#### passgo remove group/pass-name
remove is used for removing sites from the password vault. `passgo rm` is an alias of `passgo remove`.

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

#### passgo integrity
The integrity subcommand is used to manually generate and save the integrity hash of the site vault. Sometimes git issues arise and some manual intervention is necessary. Run this command first.

#### passgo remote git-url
passgo can sync your password store to a remote git repository. The remote subcommand is used to add a git remote to your local passgo git repository.

```
$ passgo remote https://github.com/ejcx/password-vault.git
$ passgo insert work/email
Enter password for work/email:
$ passgo push
```

#### passgo push
Sync your local changes to your remote git repository.

#### passgo pull
Sync your local passgo directory with your remote git repository.

```
$ passgo
└──asdf
   └──bb
$ passgo pull
$ passgo
├──asdf
|  └──bb
└──work
   └──email
```

#### passgo clone git-url
Clone a remote passgo git repository and set it as your local password store.

```
$ passgo clone https://github.com/ejcx/password-vault.git
$ passgo
├──asdf
|  └──bb
└──work
   └──email
```

#### passgo usage
Print basic usage information. `passgo help` is also an alias of `passgo usage`.

#### passgo version
Print basic version information.

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

###### Protecting Your Public Key.
Syncing a plaintext public key that is used for encrypting new site data to a remote server is risky if the remote server is malicious. Because of this, an HMAC of your public key is calculated with a separate key than your symmetric master key, based on your master password and a separate 32 byte salt.

## Threat model
The threat model of passgo assumes there are no attackers on your local machine. The passgo vault also protects itself from the remote git server by maintaining a keyed integrity hash of the password vault. The git server is unable to change site information, decrypt site information, or read passwords. Remote git servers can delete commits and changes without being detected when cloning or pulling a passwords vault. Fixing this is not possible by any password manager.
