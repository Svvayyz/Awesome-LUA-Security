# FFI-Based-HTTP-Hook
A FFI Based HTTP Hooking library.

# Sample usage:
```lua
local Callbacks = require("HttpHook.lua")

Callbacks:Register("Pre-Send", function(Request)
    print(Request.Url) -- it does not support modyfing fields (yet), will do soon :tm:
end)

Callbacks:Register("Get-Response-Body", function(Request, Buffer, BodySize)
    if Request.Url:find("amethyst.rip") then 
        -- do anything to the buffer here! (remember to resize the body size too!) 
    end 
end)

Callbacks:Register("Get-Response-Header", function(Request, Name, Buffer, HeaderSize) 
    if Name:find("User-Agent") then 
        -- do anything to the buffer here! (remember to resize the header size too!) 
    end 
end)
```
