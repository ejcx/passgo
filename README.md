# passgo [fork [`github.com/ejcx/passgo`](https://github.com/ejcx/passgo)]
## A nifty password and file manager utilizing AEAD/NaCl encryption, written in golang.  

## Package Author @ [`github.com/ejcx`](https://github.com/ejcx)  

## Mods/Settings [very minor]:  
- `passgo.go` @ `usage = ...` tabs converted to spaces [1tab = 2sp]; added `insertfile` usage  
- `passgo.go` @ line 27, set flag to `true`; password sent to clipboard instead of stdout  
   `copyPass = flag.Bool("copy", true,...`   
- Handle both username and password, per site; Add `UserSealed` to `SiteInfo`  
  
### Issues: 
- panic on `passgo show ...` @ mintty terminals of   
MINGW64 and Cygwin projects [Windows 7 x64 OS ];  
"`panic: Could not get state of terminal: The handle is  invalid.`"  
@ `pio.go:313, pc.go:122 , show.go:72, passgo.go:154`  
The culprit appears to be [`terminal.GetState(fd)`](https://github.com/golang/crypto/blob/master/ssh/terminal/util.go#L63) called @ `pio.go:311`  
-- This is a very particular use case, and of an almost obsolete operating system version.