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

HTTP_UNKNOWN       = -1
HTTP_INFORMATIONAL = 100
HTTP_SUCCESS       = 200
HTTP_REDIRECTION   = 300
HTTP_CLIENT_ERR    = 400
HTTP_SERVER_ERR    = 500

LOG_BUCKETS = {"auth", "api", "session", "saml"}

-- Returns if `haystack` starts with `needle`.
function string.startswith(haystack, needle)
    return string.sub(haystack, 1, string.len(needle)) == needle
end

-- Returns if `haystack` ends with `needle`.
function string.endswith(haystack, needle)
    return needle == "" or string.sub(haystack, -(string.len(needle))) == needle
end

function string.chopstart(haystack, needle)
    if haystack:startswith(needle) then
        return string.sub(haystack, string.len(needle) + 1, string.len(haystack))
    end

    return haystack
end

-- String split function from lua-users wiki
function string:split(sSeparator, nMax, bRegexp)
    assert(sSeparator ~= '')
    assert(nMax == nil or nMax >= 1)

    local aRecord = {}

    if self:len() > 0 then
        local bPlain = not bRegexp
        nMax = nMax or -1

        local nField, nStart = 1, 1
        local nFirst,nLast = self:find(sSeparator, nStart, bPlain)
        while nFirst and nMax ~= 0 do
            aRecord[nField] = self:sub(nStart, nFirst - 1)
            nField = nField + 1
            nStart = nLast + 1
            nFirst, nLast = self:find(sSeparator, nStart, bPlain)
            nMax = nMax - 1
        end
        aRecord[nField] = self:sub(nStart)
    end

    return aRecord
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
            return k
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

-- Wrapper function for log_redis("api", ...)
function api_log(...)
    if not config.api_logging then
        return nil
    end

    return log_redis("api", ...)
end

-- Wrapper function for log_redis("saml", ...)
function saml_log(...)
    if not config.saml_logging then
        return nil
    end

    return log_redis("saml", ...)
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

-- Functions for getting values from tables in a protected manner.
function prot_table_get(tbl, val, default)
    if not tbl then
        return nil
    end

    if not val then
        return nil
    end

    local okay, val = pcall(unprot_table_get, tbl, val)
    if not okay then
        -- More than likely could not access this key, ret default
        return default
    else
        return val
    end
end

function unprot_table_get(tbl, val)
    return tbl[val]
end

-- Determines the class of a given HTTP status
-- Returns the status class of the error:
--  HTTP_INFORMATIONAL => 1xx
--  HTTP_SUCCESS => 2xx
--  HTTP_REDIRECTION => 3xx
--  HTTP_CLIENT_ERR => 4xx
--  HTTP_SERVER_ERR => 5xx
--  HTTP_UNKNOWN => -1
function http_status_class(status)
    if not status then
        return HTTP_UNKNOWN
    end

    if status >= HTTP_INFORMATIONAL and status < HTTP_SUCCESS then
        return HTTP_INFORMATIONAL
    elseif status >= HTTP_SUCCESS and status < HTTP_REDIRECTION then
        return HTTP_SUCCESS
    elseif status >= HTTP_REDIRECTION and status < HTTP_CLIENT_ERR then
        return HTTP_REDIRECTION
    elseif status >= HTTP_SERVER_ERR and status < (HTTP_SERVER_ERR + 100) then
        return HTTP_SERVER_ERR
    else
        return HTTP_UNKNOWN
    end
end

function key_length(redis_key)
    -- Pull the length of the list in Redis.
    redis_response = rdc:exists(redis_key)
    if not redis_response then
        return 0
    end

    redis_response = rdc:llen(redis_key)
    if not redis_response then
        return 0
    end

    return redis_response
end

function log_fetch(bucket, page, limit)
    if value_in_table(LOG_BUCKETS, bucket) == nil then
        return nil
    end

    if page == nil then
        page = 0
    end

    if limit == nil then
        limit = tonumber(config.log_paginate_count or 20) or 20
    end

    local key = redis_key("log:" .. bucket)

    -- Pull a "page" of logs
    local length = key_length(key)
    if length == 0 then
        return {}
    end

    local page_start = page * limit
    local page_end = page_start + limit - 1

    redis_response = rdc:lrange(key, page_start, page_end)
    if not redis_response then
        return {}
    else
        resp = {}
        for _, val in ipairs(redis_response) do
            local real = unfurl_json(val)
            real._raw = unfurl_json(val, true)
            table.insert(resp, real)
        end
        return resp
    end
end

-- JSON data that gets put in to Redis tends to come back out in a strange
-- format. This function takes the JSON output and fixes it up for decoding.
function unfurl_json(jsonstr, no_decode)
    jsonstr = string.gsub(jsonstr, "\\/", "/")
    if not no_decode then
        return cjson.decode(jsonstr)
    else
        return jsonstr
    end
end
