# passgo [fork [`github.com/ejcx/passgo`](https://github.com/ejcx/passgo)]
## A nifty user/pass and file manager utilizing [AEAD](https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data)/[NaCl](https://godoc.org/golang.org/x/crypto/nacl) encryption.  

## Golang package author @ [`github.com/ejcx`](https://github.com/ejcx)  

## Mods/Settings:  
- Handle/encrypt both username and password, per site.  
@ `passgo show ...`, site/user displayed (stdout), and password sent to clipboard.  
-- WIP; successfully modified `insert` & `show` actions. Disabled `edit` & `rename` actions,   
which are NOT yet available and would corrupt the encrypted (`json`) vault if used.  
  Modified files: `passgo.go, insert.go, show.go, pio.go, pc.go`;  
  `import` paths modified accordingly, from `/ejcx/` to `/f06ybeast/`  
- Added `passgo clear` action; overwrites and clears clipboard.  
- Converted tabs to spaces on info @ `passgo usage`  
- Added `insertfile` action-info @ `passgo usage`   

### Issues: 
- panic on `passgo show ...` @ mintty terminals of   
MINGW64 and Cygwin projects (Windows 7 x64 OS);  
"`panic: Could not get state of terminal: The handle is  invalid.`"  
@ `pio.go:313, pc.go:122 , show.go:72, passgo.go:154`  
The culprit appears to be [`terminal.GetState(fd)`](https://github.com/golang/crypto/blob/master/ssh/terminal/util.go#L63) called @ `pio.go`:`PromptPass`  
-- This is a very particular use case; mintty, on an almost obsolete version of Windows OS.