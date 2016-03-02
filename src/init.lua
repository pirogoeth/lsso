--
-- init.lua
--
-- Initializes lsso.
-- Here, we initialize the Redis connection and do some other setup.
--

-- Include libs in the base directory in package path.
script_path = string.sub(debug.getinfo(1).source, 2, -9)
package.path = package.path .. ";" .. script_path .. "?.lua"

-- Change this to the path of your config.lua
config_path = "/usr/local/etc/lsso.config.lua"

-- Load libraries we need.
local cjson = require "cjson"
local raven = require "raven"
local redis = require "redis"

-- Load our local libraries
local util = require "util"

-- Load the config file.
dofile(config_path)

-- Globals for other parts of the application
rdc = nil -- Redis client
rvn = nil -- Raven client
request_cookie = nil -- Current request's cookie context

-- Scope mapping global table.
__scopes = {}

-- Initialize Redis
rdc = redis.connect(config.redis_address, config.redis_port)
local redis_response = nil

if config.redis_secret then
    redis_response = rdc:auth(config.redis_secret)
    if redis_response then
        ngx.log(ngx.NOTICE, "Redis: authenticated with server")
    else
        ngx.log(ngx.NOTICE, "Redis: authentication failed")
    end
end

if config.redis_db then
    redis_response = rdc:select(config.redis_db)
    if redis_response then
        ngx.log(ngx.NOTICE, "Redis: switched to database " .. config.redis_db)
    end
end

-- Initialize Raven, if needed.
if config.debug_enabled then
    rvn, err = raven:new(config.debug_dsn)
    if not rvn and err then
        ngx.log(ngx.NOTICE, "Raven: could not parse DSN: " .. err)
        config.debug_enabled = false
    end
    if config.luasec_params then
        rvn:set_luasec_params(config.luasec_params)
    end
    ngx.log(ngx.NOTICE, "Raven: initialized connection to " .. config.debug_dsn)
end
