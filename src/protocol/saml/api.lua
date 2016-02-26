--
-- protocol/saml/api.lua - SAML API handler
--

-- External library imports
local cjson = require "cjson"
local raven = require "raven"
local redis = require "redis"
local zlib = require "zlib"

-- Internal library imports
local session = require "session"
local util = require "util"

-- Protocol communication module
local saml_comm = require "protocol.saml.comm"

-- URL for this protocol
local lsso_saml = config.lsso_scheme .. "://" .. config.lsso_domain .. config.saml_endpoint

-- Special header constant for Zlib DEFLATE.
local DEFLATE_HEADER = "\120\156"

-- Processed nginx variables
nginx_uri = ngx.var.uri
nginx_server_name = ngx.var.server_name
nginx_furl = ngx.var.scheme .. "://" .. nginx_server_name .. ngx.var.request_uri
nginx_narg_url = ngx.var.scheme .. "://" .. nginx_server_name .. ngx.var.uri
nginx_client_address = ngx.var.remote_addr
nginx_client_useragent = ngx.req.get_headers()["User-Agent"]
nginx_location_scope = ngx.var.lsso_location_scope
nginx_uri_args = ngx.req.get_uri_args()
nginx_req_method = ngx.req.get_method()

-- The ngx.var API returns "" if the variable doesn't exist but is used elsewhere..
if nginx_location_scope == "" then
    nginx_location_scope = nil
end

local lsso_saml_request = nginx_narg_url:chopstart(lsso_saml)

local lsso_logging_context = {
    context = "logging",
    remote_addr = nginx_client_address,
    remote_ua = nginx_client_useragent,
    request_url = nginx_furl,
    request_scope = nginx_location_scope,
    req_id = util.generate_random_string(16),
    origin = "SAML/IdP",
}

-- Non-consistent variables
local redis_response = nil

-- API routes
if lsso_saml_request == "/SAML/Metadata" and nginx_req_method == "GET" then
    -- GET /<config.saml_endpoint>/SAML/Metadata
    --
    -- Returns the SAML IdP Metadata for this service.
    -- The Metadata file should be locatable by the config variable
    -- config.saml_metadata_file.
    -- A metadata file can be generated through a service such as SAMLTool by OneLogin:
    --   https://www.samltool.com/idp_metadata.php

    ngx.header.content_type = "text/xml"

    local metadata_file = io.open(config.saml_metadata_file, "r")
    local metadata = metadata_file:read("*a")
    metadata_file:close()

    ngx.say(metadata)
elseif lsso_saml_request == "/SAML/Redirect" and nginx_req_method == "GET" then
    -- GET /<config.saml_endpoint>/SAML/Redirect
    --
    -- The HTTP-Redirect endpoint binding for SAML2.0 negotiation.

    local saml_request = nginx_uri_args.SAMLRequest
    if not saml_request then
        ngx.say("fail")
        return
    end

    saml_request = DEFLATE_HEADER .. ngx.decode_base64(saml_request)
    local inflated = zlib.inflate(saml_request)
    ngx.say(inflated:read())
elseif lsso_saml_request == "/SAML/POST" and nginx_req_method == "POST" then
    -- POST /<config.saml_endpoint>/SAML/POST
    --
    -- HTTP-POST endpoint binding for SAML2.0 negotiation.

    -- We need to read the request body before trying to get the SAMLRequest and RelayState
    ngx.req.read_body()

    local saml_args = ngx.req.get_post_args()
    if not util.key_in_table(saml_args, "SAMLRequest") then
        ngx.say("fail")
        return
    end

    local saml_request = saml_args.SAMLRequest
    saml_request = DEFLATE_HEADER .. ngx.decode_base64(saml_request)
    local inflated = zlib.inflated(saml_request)
    ngx.say(inflated:read())
end
