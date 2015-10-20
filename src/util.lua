--
-- util.lua
--
-- Set of utils to make creating and maintaining lsso easier.
--

module('util', package.seeall)

-- External library imports
local cjson = require "cjson"
local redis = require "redis"
local socket = require "socket"

-- Useful constants.
COOKIE_EXPIRED = "Thu, 01 Jan 1970 00:00:00 UTC"

-- Returns if `haystack` starts with `needle`.
function string.startswith(haystack, needle)
    return string.sub(haystack, 1, string.len(needle)) == needle
end

-- Returns if `haystack` ends with `needle`.
function string.endswith(haystack, needle)
    return needle == "" or string.sub(haystack, -(string.len(needle))) == needle
end

-- Packs a table.
function table.pack(...)
    return { n = select("#", ...), ... }
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

function table_tostring(tbl)
    s = ""
    for k, v in pairs(tbl) do
        if type(k) ~= "string" then
            k = tostring(k)
        end
        if type(v) == "table" then
            s = s .. "; " .. k .. " -> " table_tostring(v)
        else
            s = s .. "; " .. k .. " -> " .. tostring(v)
        end
    end

    return s
end

-- Function wrapper for Raven.
function func_call(func, ...)
    if config.debug_enabled then
        return rvn:call(func, ...)
    else
        return pcall(func, ...)
    end
end

-- Function calls to simplify Redis logging.
-- Parameters:
--   log_facility - (ie., auth, session) part of the list key (lsso:log:auth)
--   ... - lines to log to Redis
function log_redis(log_facility, ...)
    local args = table.pack(...)
    local log_key = redis_key("log:" .. log_facility)
    local message_meta = {
        timestamp = ngx.now(),
        phase = ngx.get_phase()
    }
    for i=1, args.n do
        local arg = args[i]
        if type(arg) == "table" then
            if arg["context"] == "logging" then
                -- This is addition logging context, merge to meta.
                merge_tables(arg, message_meta)
                args[i] = nil
                break
            end
        end
    end
    if ngx.status ~= nil then
        -- There *should* be an active request going now.
        merge_tables({
            request = {
                status = ngx.status,
                uri = ngx.var.uri,
                method = ngx.req.get_method(),
                headers = ngx.req.get_headers()
            }
        }, message_meta)
    end
    local replies = rdc:pipeline(function(redis_pipe)
        for i=1, args.n do
            if args[i] == nil then
                goto continue
            end
            local message_data = {
                message = args[i]
            }
            merge_tables(message_meta, message_data)
            message_data = cjson.encode(message_data)
            func_call(redis_pipe.rpush, rdc, log_key, message_data)
            ::continue::
        end
    end)

    return replies
end

-- Wrapper function for log_redis("auth", ...)
function auth_log(...)
    if not config.auth_logging then
        return nil
    end

    return log_redis("auth", ...)
end

-- Wrapper function for log_redis("session", ...)
function session_log(...)
    if not config.session_logging then
        return nil
    end

    return log_redis("session", ...)
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
