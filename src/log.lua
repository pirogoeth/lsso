--
-- log.lua
--
-- Renders pages for auth and session logs using lustache.
--

-- External library imports
local cjson = require "cjson"
local lustache = require "lustache"
local raven = require "raven"
local redis = require "redis"

-- Internal library imports.
local util = require "util"

-- Vars for setting up log reading
buckets_available = {"auth", "session"}
log_bucket = ngx.var.lsso_log_bucket
log_itemslimit = tonumber(config.portal_paginate_count or ngx.var.lsso_log_paginate or 20) or 20
log_key = util.redis_key("log:" .. log_bucket)
log_page = tonumber(ngx.req.get_uri_args().page or 0) or 0

nginx_server_name = ngx.var.server_name
nginx_narg_url = ngx.var.scheme .. "://" .. nginx_server_name .. ngx.var.uri
local redis_response = nil

-- Templates
local templates = util.load_templates(config.portal_templates_path)
local partials = util.load_templates(config.portal_partials_path)

function log_length()
    -- Pull the length of the log list in Redis.
    redis_response = rdc:exists(log_key)
    if not redis_response then
        return 0
    end

    redis_response = rdc:llen(log_key)
    if not redis_response then
        return 0
    end

    return redis_response
end

function pull_log(page)
    -- Pull a "page" of logs
    local length = log_length()
    if length == 0 then
        return {}
    end

    local page_start = page * log_itemslimit
    local page_end = page_start + log_itemslimit - 1

    redis_response = rdc:lrange(log_key, page_start, page_end)
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

function unfurl_json(jsonstr, no_decode)
    jsonstr = string.gsub(jsonstr, "\\/", "/")
    if not no_decode then
        return cjson.decode(jsonstr)
    else
        return jsonstr
    end
end

local log_data = pull_log(log_page)

ngx.say(lustache:render(templates.log, {
    logs = log_data,
    config = config,
    stringify = function (self)
        return util.table_tostring(self)
    end,
}, partials))
