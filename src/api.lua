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

-- The ngx.var API returns "" if the variable doesn't exist but is used elsewhere..
if nginx_location_scope == "" then
    nginx_location_scope = nil
end

local lsso_api_request = nginx_narg_url:chopstart(lsso_api)

local lsso_logging_context = {
    context = "logging",
    remote_addr = nginx_client_address,
    remote_ua = nginx_client_useragent,
    request_url = nginx_furl,
    request_scope = nginx_location_scope,
    req_id = util.generate_random_string(16),
    origin = "api",
}

if lsso_api_request == "/_health" then
    ngx.say("okay")
elseif lsso_api_request == "/token/request" then
    if ngx.req.get_method() ~= "POST" then
        ngx.say("Unable to GET /token/request")
        return
    end

    -- POST /token/request requires these parameters:
    --  - username: OAuth username [required]
    --  - password: OAuth password [required]
    --  - expire: number of seconds until token expiry [optional; defaults to cookie_lifetime]
    --  - scope: scope to create the access token under [option; defaults to oauth_auth_scope]
    --
    -- This API routine will essentially go through the entire session generation process, but
    -- it will just return an access token, which can be used to log in on the portal.
    ngx.req.read_body()
    local args = ngx.req.get_post_args()

    if not util.key_in_table(args, "username") then
        util.api_log("Attempted token request without `username` field.", lsso_logging_context)
        local err = {
            code = 400,
            message = "Missing `username` field",
        }
        err = cjson.encode(err)
        ngx.say(err)
        return
    end

    if not util.key_in_table(args, "password") then
        util.api_log("Attempted token request without `password` field.", lsso_logging_context)
        local err = {
            code = 400,
            message = "Missing `password` field",
        }
        err = cjson.encode(err)
        ngx.say(err)
        return
    end

    if not util.key_in_table(args, "expire") then
        util.api_log("Setting default expiry of " .. config.cookie_lifetime .. " for access token",
                     lsso_logging_context)
        args["expire"] = config.cookie_lifetime
    else
        expire = tonumber(args["expire"]) or config.cookie_lifetime
        if expire > config.cookie_lifetime then
            util.api_log("Attempted to request access token with expiry over " .. config.cookie_lifetime,
                         lsso_logging_context)
            args["expire"] = config.cookie_lifetime
        else
            args["expire"] = expire
        end
    end

    if not util.key_in_table(args, "scope") then
        util.api_log("Setting default scope of " .. config.oauth_auth_scope .. " for access token",
                     lsso_logging_context)
        args["scope"] = config.oauth_auth_scope
    else
        -- XXX - add whitelisted/blacklisted scopes for token requests
    end

    -- Create auth args
    local auth_table = {}
    util.merge_tables(config.oauth_auth_context, auth_table)

    -- Add auth data to auth table, escape user-provided data
    auth_table["username"] = ngx.escape_uri(args["username"])
    auth_table["password"] = ngx.escape_uri(args["password"])
    auth_table["scope"] = ngx.escape_uri(args["scope"])

    -- Merge details into the logging context
    util.merge_tables({
        lsso_username = auth_table["username"],
        lsso_scope = auth_table["scope"],
    }, lsso_logging_context)

    auth_table = ngx.encode_args(auth_table)

    ngx.req.set_header("Content-Type", "application/x-www-form-urlencoded")
    local okay, oauth_res = util.func_call(ngx.location.capture, config.oauth_auth_endpoint, {
        method = ngx.HTTP_POST,
        body = auth_table,
    })

    if util.http_status_class(oauth_res.status) == util.HTTP_SERVER_ERR then
        util.api_log("Upstream communication error: " .. oauth_res.body, lsso_logging_context)
        local err = {
            code = oauth_res.status,
            message = "Upstream communication error",
        }
        err = cjson.encode(err)
        ngx.say(err)
        return
    end

    -- Decode the OAuth response and make sure it did not return an error
    local auth_response = cjson.decode(oauth_res.body)

    -- Check for an OAuth error
    if util.key_in_table(auth_response, "error") then
        -- Auth request failed, process the information and redirect.
        util.auth_log("Received error from OAuth backend: " .. oauth_res.body)
        if auth_response["error"] == "invalid_scope" then
            local err = {
                code = oauth_res.status,
                message = auth_response["error"],
            }
            err = cjson.encode(err)
            ngx.say(err)
            return
        else
            local err = {
                code = oauth_res.status,
                message = auth_response["error"],
            }
            err = cjson.encode(err)
            ngx.say(err)
            return
        end
    else
        -- Success. Log it!
        util.auth_log("Auth success: " .. args["username"], lsso_logging_context)
    end

    -- Steps:
    --  1) Create session first
    --  2) Create access token which will resolve to a session.
    --  3) Give the client the access token to enter on the portal
    --  4) Keep session a secret UNTIL the access code is entered in the portal
    --     and assigned to the end user. At this point, the access code will be
    --     removed from the system.

    -- Store token information in Redis.
    local session_key = util.generate_random_string(64) -- XXX - make length configurable?
    local session_salt = util.generate_random_string(8) -- Again, configurable length.
    local rd_sess_key = util.redis_key("session:" .. session_key)
    local current_time = ngx.now()

    -- Save the session in Redis
    rdc:pipeline(function(p)
        p:hset(rd_sess_key, "username", args["username"])
        p:hset(rd_sess_key, "token", auth_response.access_token)
        p:hset(rd_sess_key, "scope", auth_response.scope)
        p:hset(rd_sess_key, "created", current_time)
        p:hset(rd_sess_key, "remote_addr", nginx_client_address)
        p:hset(rd_sess_key, "salt", session_salt)
        p:hset(rd_sess_key, "origin", "api acctok")
        p:expire(rd_sess_key, args["expire"])
    end)

    util.session_log("Created new session: " .. session_key, lsso_logging_context)

    local access_token = util.generate_random_string(16) -- XXX - make length configurable?
    local rd_acc_key = util.redis_key("acctok:" .. access_token)

    rdc:pipeline(function(p)
        p:hset(rd_acc_key, "created", current_time)
        p:hset(rd_acc_key, "session", session_key)
        p:expire(rd_acc_key, args["expire"])
    end)

    util.api_log("Created new access token: " .. access_token, lsso_logging_context)

    local access_data = {
        code = 200,
        message = "Access token created",
        token = access_token,
        expires = current_time + args["expire"],
        username = args["username"],
    }
    access_data = cjson.encode(access_data)

    ngx.say(access_data)
end
