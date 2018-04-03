[![Build Status](https://travis-ci.org/f06ybeast/passgo.svg?branch=master)](https://travis-ci.org/f06ybeast/passgo)
[![GoDoc](https://godoc.org/github.com/f06ybeast/passgo?status.svg)](https://godoc.org/github.com/f06ybeast/passgo)
![Go Report Card](https://goreportcard.com/badge/github.com/f06ybeast/passgo)
# passgo [fork [`github.com/ejcx/passgo`](https://github.com/ejcx/passgo)]
## A user/pass and file manager utilizing [AEAD](https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data)/[NaCl](https://godoc.org/golang.org/x/crypto/nacl) encryption.  
(The original repo handles site passwords, but not usernames.)
## Mods/Settings @ this fork:  
- Handle both usernames and passwords per site.  
  (The site and username are printed, and password is sent to clipboard.)    
- Add full sorting of groups/names, and vault entries total, on vault listing.  
- Add `clear` action, which overwrites and then clears the clipboard.   
- Prevent empty entries at user/pass/site/file-name on any `insert`/`rename`/`edit` action. 

NOTE: the `JSON` vault for this fork is **not compatible**   
with any that do not abide its new user/pass schema.

See `notes.md` for more detail.
