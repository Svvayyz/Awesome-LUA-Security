local ffi = require("ffi")

local Mem = {}
do -- Memory 
    function Mem:Cast(Object, TypeString)
        return ffi.cast(TypeString, Object)
    end 

    function Mem:SizeOf(TypeString)
        return ffi.sizeof(TypeString)
    end 

    function Mem:Defined(TypeString)
        return pcall(function()
            Mem:SizeOf(TypeString)
        end)
    end 

    function Mem:CDef(TypeString)
        ffi.cdef(TypeString)
    end 

    function Mem:TypeOf(TypeString)
        return ffi.typeof(TypeString)
    end 

    if not Mem:Defined("SteamAPICall_t") then 
        Mem:CDef([[
            typedef uint64_t SteamAPICall_t;

            struct SteamAPI_callback_base_vtbl {
                void(__thiscall *run1)(struct SteamAPI_callback_base *, void *, bool, uint64_t);
                void(__thiscall *run2)(struct SteamAPI_callback_base *, void *);
                int(__thiscall *get_size)(struct SteamAPI_callback_base *);
            };

            struct SteamAPI_callback_base {
                struct SteamAPI_callback_base_vtbl *vtbl;
                uint8_t flags;
                int id;
                uint64_t api_call_handle;
                struct SteamAPI_callback_base_vtbl vtbl_storage[1];
            };
        ]])
    end 

    if not Mem:Defined("http_HTTPRequestHandle") then 
        Mem:CDef([[
            typedef uint32_t http_HTTPRequestHandle;
            typedef uint32_t http_HTTPCookieContainerHandle;

            enum http_EHTTPMethod {
                k_EHTTPMethodInvalid,
                k_EHTTPMethodGET,
                k_EHTTPMethodHEAD,
                k_EHTTPMethodPOST,
                k_EHTTPMethodPUT,
                k_EHTTPMethodDELETE,
                k_EHTTPMethodOPTIONS,
                k_EHTTPMethodPATCH,
            };
        ]])
    end 
end 

local Client = {}
function Client:SetEventCallback(Name, Function)
    return client.set_event_callback(Name, Function)
end 

local Steam = {}
do -- Steam 
    Steam.ClientContextPtr = client.find_signature("client_panorama.dll", "\xB9\xCC\xCC\xCC\xCC\xE8\xCC\xCC\xCC\xCC\x83\x3D\xCC\xCC\xCC\xCC\xCC\x0F\x84") or error("Invalid siggy!")
    Steam.ClientContextPtr = Mem:Cast(Steam.ClientContextPtr, "uintptr_t") + 1 -- offset: 1
    Steam.ClientContext = Mem:Cast(Steam.ClientContextPtr, "uintptr_t*")[0]

    Steam.HTTP = Mem:Cast(Steam.ClientContext, "uintptr_t*")[12] -- crashin here!
end 

local Hooks = {}
do -- Hook system 
    function Hooks:DetourToAddress(Detour, TypeString)
        local Detour = Mem:Cast(Detour, TypeString)

        local DetourPointer = Mem:Cast(Detour, "void*") -- alloc the method as a void*
        local DetourAddress = Mem:Cast(DetourPointer, "unsigned int*") -- turn it into a integer pointer

        return DetourAddress
    end 

    function Hooks:GetVTable(VTableAddress)
        return Mem:Cast(VTableAddress, "void***")[0]
    end 

    function Hooks:GetVFunc(VTable, Index)
        return Mem:Cast(
            Hooks:GetVTable(VTable)[Index], 
            "unsigned int*"
        )
    end 

    function Hooks:Hook(Index, TypeString, Detour)
        local OriginalPointer = Hooks:GetVFunc(Steam.HTTP, Index) -- Steam.HTTP as a vtable!
        local Original = Mem:Cast(OriginalPointer, TypeString)

        local F = function(...)
            return Detour(Original, Steam.HTTP, ...) -- Original, ThisPtr, ... 
        end 
        local DetourAddress = Hooks:DetourToAddress(F, TypeString)

        local Hook = {
            Address = OriginalPointer,
            Detour = DetourAddress
        }
        local HookMetaTable = {
            __index = {
                Modify = function(Self, V)
                    Self.Address = V and Self.Detour or Self.Address
                end,

                Enable = function(Self)
                    Self:Modify(true)
                end,

                Disable = function(Self)
                    Self:Modify(false)
                end 
            }
        }
        setmetatable(Hook, HookMetaTable)

        Hook:Enable()

        table.insert(Hooks, Hook)

        return Hook
    end 
end 

local Requests = {}
local Cookies = {}
local Callbacks = {}

do -- Callbacks 
    function Callbacks:Register(Name, Function)
        if not Callbacks[Name] then 
            Callbacks[Name] = {}
        end 

        table.insert(
            Callbacks[Name],
            Function
        )
    end 

    function Callbacks:Fire(Name, ...)
        if not Callbacks[Name] then 
            return -- we dont have any callbacks registered
        end 

        for _, Function in pairs(Callbacks[Name]) do 
            Function(...)
        end 
    end 
end 

do -- Actual Hooks 
    -- CreateHTTPRequest
    Hooks:Hook(
        0,
        "http_HTTPRequestHandle(__thiscall*)(uintptr_t, enum http_EHTTPMethod, const char*)",
        function(Original, This, HttpMethod, Url)
            local RequestHandle = Original(This, HttpMethod, Url)

            Requests[RequestHandle] = {
                Url = Url,
                Method = HttpMethod,

                Data = {
                    Body = {
                        ContentType = 0, Body = "", Length = 0
                    },
                    UserAgent = "",

                    Headers = {},
                    Cookies = {},
                    Parameters = {}
                },

                Response = {}
            }

            return RequestHandle
        end
    )

    -- SetHTTPRequestHeaderValue
    Hooks:Hook(
        3,
        "bool(__thiscall*)(uintptr_t, http_HTTPRequestHandle, const char*, const char*)",
        function(Original, This, RequestHandle, Name, Value)
            table.insert(
                Requests[RequestHandle].Data.Headers, 
                {
                    Name = Name, 
                    Value = Value
                }
            ) 
            
            return Original(This, RequestHandle, Name, Value)
        end 
    )

    -- SetHTTPRequestGetOrPostParameter
    Hooks:Hook(
        4,
        "bool(__thiscall*)(uintptr_t, http_HTTPRequestHandle, const char*, const char*)",
        function(Original, This, RequestHandle, Name, Value)
            table.insert(
                Requests[RequestHandle].Data.Parameters, 
                {
                    Name = Name, 
                    Value = Value
                }
            ) 

            return Original(This, RequestHandle, Name, Value)
        end 
    )

    -- SendHTTPRequest
    Hooks:Hook(
        5,
        "bool(__thiscall*)(uintptr_t, http_HTTPRequestHandle, SteamAPICall_t*)",
        function(Original, This, RequestHandle, CallbackHandle)
            Callbacks:Fire(
                "Pre-Send",
                Requests[RequestHandle]
            )

            return Original(This, RequestHandle, CallbackHandle)
        end 
    )

    -- SendHTTPRequestAndStreamResponse
    Hooks:Hook(
        6,
        "bool(__thiscall*)(uintptr_t, http_HTTPRequestHandle, SteamAPICall_t*)",
        function(Original, This, RequestHandle, CallbackHandle)
            return Original(This, RequestHandle, CallbackHandle)
        end 
    )

    -- SendHTTPRequestAndStreamResponse
    Hooks:Hook(
        7,
        "bool(__thiscall*)(uintptr_t, http_HTTPRequestHandle, SteamAPICall_t*)",
        function(Original, This, RequestHandle, CallbackHandle)
            return Original(This, RequestHandle, CallbackHandle)
        end 
    )

    -- GetHTTPResponseHeaderSize
    Hooks:Hook(
        9,
        "bool(__thiscall*)(uintptr_t, http_HTTPRequestHandle, const char*, uint32_t*)",
        function(Original, This, RequestHandle, Name, HeaderSizePtr)
            return Original(This, RequestHandle, Name, HeaderSizePtr)
        end 
    )

    -- GetHTTPResponseHeaderValue
    Hooks:Hook(
        10,
        "bool(__thiscall*)(uintptr_t, http_HTTPRequestHandle, const char*, uint8_t*, uint32_t)",
        function(Original, This, RequestHandle, Name, Buffer, HeaderSize)
            local Result = Original(This, RequestHandle, Name, Buffer, HeaderSize)

            Callbacks:Fire("Get-Response-Header", Requests[RequestHandle], Name, Buffer, HeaderSize)

            return Result
        end 
    )

    -- GetHTTPResponseBodyData
    Hooks:Hook(
        12,
        "bool(__thiscall*)(uintptr_t, http_HTTPRequestHandle, uint8_t*, uint32_t)",
        function(Original, This, RequestHandle, Buffer, BodySize)
            local Result = Original(This, RequestHandle, Buffer, BodySize)

            Callbacks:Fire("Get-Response-Body", Requests[RequestHandle], Buffer, BodySize)

            return Result
        end 
    )

    -- GetHTTPStreamingResponseBodyData
    Hooks:Hook(
        13,
        "bool(__thiscall*)(uintptr_t, http_HTTPRequestHandle, uint32_t, uint8_t*, uint32_t)",
        function(Original, This, RequestHandle, Offset, Buffer, BytesReceived)
            local Result = Original(This, RequestHandle, Offset, Buffer, BytesReceived)

            Callbacks:Fire("Get-Body", Requests[RequestHandle], Offset, Buffer, BytesReceived)

            return Result
        end 
    )

    -- SetHTTPRequestRawPostBody
    Hooks:Hook(
        16,
        "bool(__thiscall*)(uintptr_t, http_HTTPRequestHandle, uint32_t, uint8_t*, uint32_t)",
        function(Original, This, RequestHandle, ContentType, Body, Length)
            Requests[RequestHandle].Data.Body = {
                ContentType = ContentType,
                Body = Body,
                Length = Length
            }

            return Original(This, RequestHandle, ContentType, Body, Length)
        end 
    )

    -- SetCookie
    Hooks:Hook(
        19,
        "bool(__thiscall*)(uintptr_t, http_HTTPCookieContainerHandle, const char*, const char*, const char*)",
        function(Original, This, CookieContainer, Host, Url, Name, Value)
            if not Cookies[CookieContainer] then 
                Cookies[CookieContainer] = {} -- create if it does not exist yet!
            end 
    
            table.insert(
                Cookies[CookieContainer],
                {
                    Host = Host,
                    Url = Url, 
    
                    Data = {
                        Name = Name, 
                        Value = Value 
                    }
                }
            )

            return Original(This, CookieContainer, Host, Url, Name, Value)
        end 
    )

    -- SetHTTPRequestCookieContainer
    Hooks:Hook(
        20,
        "bool(__thiscall*)(uintptr_t, http_HTTPRequestHandle, http_HTTPCookieContainerHandle)",
        function(Original, This, RequestHandle, CookieContainer)
            Requests[RequestHandle].Data.Cookies = Cookies[CookieContainer] -- set the cookie container!

            return Original(This, RequestHandle, CookieContainer)
        end 
    )

    -- SetHTTPRequestUserAgentInfo
    Hooks:Hook(
        21,
        "bool(__thiscall*)(uintptr_t, http_HTTPRequestHandle, const char*)",
        function(Original, This, RequestHandle, UserAgentInfo)
            Requests[RequestHandle].Data.UserAgent = UserAgentInfo

            return Original(This, RequestHandle, UserAgentInfo)
        end 
    )
end 

Client:SetEventCallback("shutdown", function()
    for _, Hook in pairs(Hooks) do 
        if type(Hook) ~= "table" then goto continue end 

        Hook:Disable() -- remove all hooks on shutdown lol

        ::continue::
    end 
end)

return Callbacks
