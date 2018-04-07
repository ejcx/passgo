## Mods/Settings @ this fork:  
- Handle both usernames and passwords per site.  
  The site and username are printed; password is sent to clipboard.    
- Add full sorting of groups/names, and vault entries total, on vault listing.  
   `innerPrefix` glyph changed from `U+007C` to `U+2502` code point.  
- Prevent empty entries at user/pass/site/file-name on any `insert`/`rename`/`edit` action.  
- Add `clear` action, which overwrites and then clears the clipboard.   
- Add usage-info for the `insertfile` action.  
- Convert text tabs to spaces at `usage` action.  
- Modified Go `import` paths from `/ejcx/` to `/f06ybeast/`,   
  as necessary to handle changes/dependencies. 

NOTE: the `JSON` vault for this fork is **not compatible** with   
any others that do not abide the user/pass schema.

### Tested Sucessfully 
- @ Linux (CentOS 7), local/remote; remote clipboard requires X11 (`ssh -X ...`).  
- @ Windows, `cmd` and `PowerShell` ("terminal" pkg fails on `mintty`; MINGW64/Cygwin).   

### ToDo:
- Add a loop-mode on `show`, in the absence of a site/file argument, where the master  
  password is required only once, allowing more site/file requests thereafter. 

### Dev/Branches 
- d1  
Combine all user prompts for credentials into `pio.PromptCreds` `function`,    
which returns `pio.Creds`, a `struct` used by `edit.Edit` and `insert.Insert`.  


