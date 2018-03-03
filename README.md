# passgo [fork [`github.com/ejcx/passgo`](https://github.com/ejcx/passgo)]
## A nifty user/pass and file manager utilizing [AEAD](https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data)/[NaCl](https://godoc.org/golang.org/x/crypto/nacl) encryption.  

## Golang package author @ [`github.com/ejcx`](https://github.com/ejcx)  

## Mods/Settings @ this fork:  
- `insert` & `show` actions now handle both username and password, per site.   
- `show` action prints site and username, and sends password to clipboard.  
- `clear` action added; overwrites and clears clipboard.  
- `usage` action; text tabs converted to spaces, and other minor mods.  
Also added usage-info for the `insertfile` action.  
- `edit` & `rename` actions disabled; not yet available and would corrupt  
the encrypted (`json`) vault if used, so use `remove` then `insert` instead.  
- Package files modified: `passgo.go`, `insert.go`, `show.go`,`pio.go`, `pc.go` .  
 Go `import` paths modified accordingly,   from `/ejcx/` to `/f06ybeast/` . 

### Issues: 
- panic on `passgo show ...` @ mintty terminals of   
MINGW64 and Cygwin projects (Windows 7 x64 OS);  
"`panic: Could not get state of terminal: The handle is  invalid.`"  
The culprit appears to be [`terminal.GetState(fd)`](https://github.com/golang/crypto/blob/master/ssh/terminal/util.go#L63) called @ `pio.go`:`PromptPass`  
-- This is a very particular use case; mintty, on an almost obsolete version of Windows OS.