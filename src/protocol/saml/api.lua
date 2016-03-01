--
-- protocol/saml/api.lua - SAML API handler
--

-- External library imports
local cjson = require "cjson"
local raven = require "raven"
local redis = require "redis"
local xml = require "xml"
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

    util.http_rtype("text/xml")

    local metadata_file = io.open(config.saml_metadata_file, "r")
    local metadata = metadata_file:read("*a")
    metadata_file:close()

    ngx.say(metadata)
elseif lsso_saml_request == "/SAML/Redirect" and nginx_req_method == "GET" then
    -- GET /<config.saml_endpoint>/SAML/Redirect
    --
    -- The HTTP-Redirect endpoint binding for SAML2.0 negotiation.

    util.http_rtype("text/xml")

    local saml_request = nginx_uri_args.SAMLRequest
    if not saml_request then
        ngx.say("fail")
        return
    end

    saml_request = DEFLATE_HEADER .. ngx.decode_base64(saml_request)
    local inflated = zlib.inflate(saml_request)
    saml_request = inflated:read()
    inflated:close()

    -- Make sure this SAML request is valid.
    --  Steps:
    --   1) Ensure samlp:AuthnRequest/xmlns:samlp matches SAML 2.0 proto version
    --   2) Ensure samlp:AuthnRequest/AssertionConsumerServiceURL is valid
    --   3) Ensure samlp:AuthnRequest/Destination matches our URL
    --   4) Ensure samlp:AuthnRequest/saml:Issuer is an allowed issuer
    --   5) Check request signature, if necessary.
    --

    local req = xml.load(saml_request)
    local resp = saml_comm.create_saml_response()

    -- Set the SAML Response issuer
    do
        local issuer = xml.find(resp, "saml:Issuer")
        table.insert(issuer, config.saml_issuer_entity)
    end

    -- Check for protocol version conflicts
    if req["xmlns:samlp"] ~= saml_comm.SAML_PROTO.V2_0 then
        local status = xml.find(resp, "samlp:StatusCode")
        status.Value = saml_comm.SAML_STATUS.VERSION_MISMATCH
        resp = xml.dump(resp)
        ngx.say(resp)
        return
    end

    -- Check the original ID
    do
        local id = req.ID
        if #id ~= 33 or not id:startswith("_") then
            local status = xml.find(resp, "samlp:StatusCode")
            status.Value = saml_comm.SAML_STATUS.REQUESTER
            resp = xml.dump(resp)
            ngx.say(resp)
            return
        else
            -- This ID is valid, include it in the response.
            resp.InResponseTo = id
        end
    end

    -- Check AssertionConsumerServiceURL
    -- XXX: TODO

    -- Check Destination
    do
        if req.Destination ~= nginx_narg_url then
            local status = xml.find(resp, "samlp:StatusCode")
            status.Value = saml_comm.SAML_STATUS.REQUESTER
            resp = xml.dump(resp)
            ngx.say(resp)
            return
        end
    end

    -- Check saml:Issuer
    do
        local issuer = xml.find(req, "saml:Issuer")
        issuer = issuer[1]

        if not util.value_in_table(config.saml_allowed_issuers, issuer) then
            local status = xml.find(resp, "samlp:StatusCode")
            status.Value = saml_comm.SAML_STATUS.REQ_DENIED
            resp = xml.dump(resp)
            ngx.say(resp)
            return
        end
    end

    -- Set the success status
    do
        local status = xml.find(resp, "samlp:StatusCode")
        status.Value = saml_comm.SAML_STATUS.SUCCESS
    end

    -- At this point, check if the user has a session open on the SSO.
    -- If they do, send the authorization to the SP. Otherwise, set the user's
    -- redirect to this URL and try to get authorization. Once authorized, we
    -- can redirect back here, collect the token, and set up the SAML session tokens
    -- in the store. Then, we use ProtocolBinding to determine the session forwarding method
    -- and then forward the proper session information to the SP.
    --
    -- TODO~!

    -- XXX: Print the response. This is not the proper workflow, but we're figuring it out.
    resp = xml.dump(resp)
    ngx.say(resp)
    return
elseif lsso_saml_request == "/SAML/POST" and nginx_req_method == "POST" then
    -- POST /<config.saml_endpoint>/SAML/POST
    --
    -- HTTP-POST endpoint binding for SAML2.0 negotiation.

    -- We need to read the request body before trying to get the SAMLRequest and RelayState
    ngx.req.read_body()

    util.http_rtype("text/xml")

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
