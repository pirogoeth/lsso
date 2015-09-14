--
-- util.lua
--
-- Set of utils to make creating and maintaining lsso easier.
--

module('util', package.seeall)

-- External library imports
local redis = require "redis"
local socket = require "socket"


-- Returns if `haystack` starts with `needle`.
function string.startswith(haystack, needle)
    return string.sub(haystack, 1, string.len(needle)) == needle
end

-- Returns if `haystack` ends with `needle`.
function string.endswith(haystack, needle)
    return needle == "" or string.sub(haystack, -(string.len(needle))) == needle
end

-- Custom Redis client commands and callbacks.
redis.commands.hgetall = redis.command('hgetall', {
    response = function(reply, command, ...)
        local new_reply = {}
        for i = 1, #reply, 2 do new_reply[reply[i]] = reply[i + 1] end
        return new_reply
    end
})

-- Random string generator. Good for generating a nonce or key.
function generate_random_string(length)
    if length < 1 then
        return nil
    end

    -- Seed the random number generator.
    math.randomseed(tonumber(tostring(socket.gettime() * 10000):reverse()))

    local s = ""
    -- Use math.random and string.char to get random ints within visible ASCII range,
    --  then, turn it in to a character and append to `s`.
    for i = 1, length do
        s = s .. string.char(math.random(33, 126))
    end

    s = ngx.encode_base64(s)
    if string.len(s) > length then
        s = string.sub(s, 1, length)
    end

    return s
end

-- Checks if a table contains a key.
function key_in_table(tabsrc, key)
    for k, v in pairs(tabsrc) do
        if k == key then
            return true
        end
    end

    return false
end

-- Checks if a value is in a table. If so, return the key.
function value_in_table(tabsrc, val)
    for k, v in pairs(tabsrc) do
        if v == val then
            return key
        end
    end

    return nil
end

-- Merges items from table `from` into `onto`, modifying `onto` directly.
function merge_tables(from, onto)
    for k, v in pairs(from) do
        if type(v) == "table" then
            if type(onto[k] or nil) == "table" then
                merge_tables(v, onto[k])
            else
                onto[k] = v
            end
        else
            onto[k] = v
        end
    end

    return onto
end

-- Function wrapper for Raven.
function func_call(func, ...)
    if config.debug_enabled then
        return rvn:call(func, ...)
    else
        return pcall(func, ...)
    end
end

-- Convenience functions for Redis keys and cookies
function redis_key(key_name)
    return config.redis_key_prefix .. key_name
end

function cookie_key(key_name)
    return config.cookie_prefix .. key_name
end

function get_cookie(cookie_name)
    local cookie = "cookie_" .. cookie_name
    return ngx.var[cookie]
end

function set_cookies(cookies)
    local cset = ngx.header["Set-Cookie"] or {}

    if type(cookies) == "string" then
        cookies = {cookies}
    end

    for _, v in pairs(cookies) do
        print("Cookie: " .. v)
        table.insert(cset, v)
    end
    ngx.header["Set-Cookie"] = cset
end

function delete_cookie(cookie_name)
    local cookies = ngx.header["Set-Cookie"] or {}
    if type(cookies) == "string" then
        cookies = {cookies}
    end

    for k, v in pairs(cookies) do
        local name = string.match(value, "(.-)=")
        if name == cookie_name then
            table.remove(cookies, key)
        end
    end

    ngx.header["Set-Cookie"] = cookies or {}
end

function create_cookie(params)
    local cookie = ""
    for k, v in pairs(params) do
        cookie = cookie .. k .. "=" .. v .. "; "
    end
    return cookie
end
