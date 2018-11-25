[![Build Status](https://travis-ci.org/f06ybeast/passgo.svg?branch=userpass)](https://travis-ci.org/f06ybeast/passgo)
[![GoDoc](https://godoc.org/github.com/f06ybeast/passgo?status.svg)](https://godoc.org/github.com/f06ybeast/passgo)
![Go Report Card](https://goreportcard.com/badge/github.com/f06ybeast/passgo)
# passgo [fork [`github.com/ejcx/passgo`](https://github.com/ejcx/passgo)]
## A user/pass and file manager utilizing [AEAD](https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data)/[NaCl](https://godoc.org/golang.org/x/crypto/nacl) encryption.  
- The original repo handles site passwords, but not usernames.
## Mods/Settings @ this fork:  
- Add usernames handling. The site name and username are printed;  
  the password is sent to clipboard (default behavior; see '`passgo usage`').    
- Add loop-mode, where the master password is entered once, and then  
  sites' user/pass is accessed thereafter by a user-prompt for site name.    
- Add sorting of groups/names, and show vault entries total, on vault listing.  
- Add `clear` option, which overwrites and then clears the clipboard.   
- Prevent empty-string vault entries of site name, username or password.

NOTE: the `JSON` vault for this fork is **not compatible**   
with any that do not abide its new user/pass schema.

[See `notes.md`](notes.md) for more detail.
