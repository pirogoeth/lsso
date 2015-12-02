--
-- api.lua
--
-- API for performing actions on LSSO.
--

-- External library imports
local cjson = require "cjson"

-- Internal library imports
local session = require "session"
local util = require "util"

local lsso_api = config.lsso_scheme .. "://" .. config.lsso_domain .. config.api_endpoint

nginx_uri = ngx.var.uri
nginx_server_name = ngx.var.server_name
nginx_furl = ngx.var.scheme .. "://" .. nginx_server_name .. ngx.var.request_uri
nginx_narg_url = ngx.var.scheme .. "://" .. nginx_server_name .. ngx.var.uri
nginx_client_address = ngx.var.remote_addr
nginx_client_useragent = ngx.req.get_headers()["User-Agent"]
nginx_location_scope = ngx.var.lsso_location_scope

local lsso_api_request = nginx_narg_url:chopstart(lsso_api)

lsso_logging_context = {
    context = "logging",
    remote_addr = nginx_client_address,
    remote_ua = nginx_client_useragent,
    request_url = nginx_furl,
    request_scope = nginx_location_scope,
    req_id = util.generate_random_string(16),
}

if lsso_api_request == "/_health" then
    ngx.say("okay")
end
