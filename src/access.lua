--
-- access.lua
--
-- Script used by the nginx access_by_lua_file directive to determine
-- if a user can access a protected resource.
--

-- External library imports
local cjson = require "cjson"
local raven = require "raven"
local redis = require "redis"

-- Internal library imports
local util = require "util"

-- Some shorthand.
local lsso_login = config.lsso_scheme .. "://" .. config.lsso_domain .. config.lsso_login_redirect
local lsso_capture = config.lsso_scheme .. "://" .. config.lsso_domain .. config.lsso_capture_location
local redis_response = nil


nginx_uri = ngx.var.uri
nginx_furl = ngx.var.scheme .. "://" .. ngx.var.server_name .. ngx.var.request_uri
nginx_client_address = ngx.var.remote_addr

-- Functions for session validation.
function resolve_session(session_token)
    -- Resolve a session token to an auth token.
    rd_sess_key = util.redis_key("session:" .. session_token)
    redis_response = rdc:exists(rd_sess_key)
    if not redis_response then
        return nil
    end

    redis_response = rdc:hgetall(rd_sess_key)
    if not redis_response then
        return nil
    end

    return redis_response
end

function validate_token(token_response)
    -- Take a response from resolve_session() and validate with oauth server.
    local token = token_response.token
    local username = token_response.username

    local token_table = {
        access_token = token,
        username = username,
        scope = "ALL"
    }
    token_table = ngx.encode_args(token_table)

    ngx.req.set_header("Content-Type", "application/x-www-form-urlencoded")
    local okay, oauth_res = util.func_call(ngx.location.capture, config.oauth_token_endpoint, {
        method = ngx.HTTP_POST,
        body = token_table
    })

    local response_status = oauth_res.status
    if response_status ~= 200 then
        return false
    else
        return true
    end
end

if nginx_furl == lsso_capture then
    if ngx.req.get_method() ~= "POST" then
        ngx.redirect(lsso_login)
    end

    user_session = util.get_cookie(util.cookie_key("Session"))
    if user_session then
        ngx.log(ngx.NOTICE, "Checking existing user session: " .. user_session)
        local okay, session = util.func_call(resolve_session, user_session)
        if okay and session then
            local okay, is_valid = util.func_call(validate_token, session)
            if is_valid then
                ngx.log(ngx.NOTICE, "User session [" .. user_session .. "] is valid.")
                user_redirect = util.get_cookie(util.cookie_key("Redirect"))
                if user_redirect then
                    util.delete_cookie(util.cookie_key("Redirect"))
                    ngx.redirect(user_redirect)
                else
                    ngx.redirect(config.lsso_default_redirect)
                end
            else
                ngx.log(ngx.NOTICE, "User session[" .. user_session .. "] is NOT valid!")
                util.delete_cookie(util.cookie_key("Session"))
                util.delete_cookie(util.cookie_key("Redirect"))
            end
        end
    end

    -- Since we're here, this should be a POST request with a username and password.
    ngx.req.read_body()
    local credentials = ngx.req.get_post_args()

    if not util.key_in_table(credentials, "user") then
        ngx.redirect(lsso_login) -- XXX - needs error message
    end

    if not util.key_in_table(credentials, "password") then
        ngx.redirect(lsso_login) -- XXX - needs error message
    end

    -- Create the auth table and convert it to JSON.
    local auth_table = {}
    util.merge_tables(config.oauth_auth_context, auth_table)
    auth_table["username"] = ngx.escape_uri(credentials["user"])
    auth_table["password"] = ngx.escape_uri(credentials["password"])
    auth_table = ngx.encode_args(auth_table)

    -- Perform the token request.
    ngx.req.set_header("Content-Type", "application/x-www-form-urlencoded")
    local okay, oauth_res = util.func_call(ngx.location.capture, config.oauth_auth_endpoint, {
        method = ngx.HTTP_POST,
        body = auth_table
    })

    local auth_response = cjson.decode(oauth_res.body)
    if util.key_in_table(auth_response, "error") then
        -- Auth request failed, process the information and redirect.
        -- XXX - process the auth response
        ngx.redirect(lsso_login) -- XXX - needs error message
    end

    -- Store token information in Redis.
    session_key = util.generate_random_string(64) -- XXX - make length configurable?
    rd_sess_key = util.redis_key("session:" .. session_key)

    util.set_cookies({
        util.create_cookie(util.cookie_key("Session"), session_key, {
            ["Path"] = "/",
            ["Domain"] = "." .. config.cookie_domain,
            ["Max-Age"] = config.cookie_lifetime
        })
    })

    rdc:pipeline(function(p)
        p:hset(rd_sess_key, "username", credentials["user"])
        p:hset(rd_sess_key, "token", auth_response.access_token)
        p:hset(rd_sess_key, "created", ngx.now())
        p:hset(rd_sess_key, "remote_addr", nginx_client_address)
        p:expire(rd_sess_key, config.cookie_lifetime)
    end)

    -- XXX - need to do processing here!
    user_redirect = util.get_cookie(util.cookie_key("Redirect"))
    if user_redirect then
        util.delete_cookie(util.cookie_key("Redirect"))
        ngx.redirect(user_redirect)
    else
        ngx.redirect(config.lsso_default_redirect)
    end
elseif nginx_uri ~= config.lsso_capture_location then
    -- We're at anything other than the auth verification location.
    -- Let's do this!
    user_session = util.get_cookie(util.cookie_key("Session"))
    if user_session then
        ngx.log(ngx.NOTICE, "Checking existing user session: " .. user_session)
        local okay, session = util.func_call(resolve_session, user_session)
        if okay and session then
            local okay, is_valid = util.func_call(validate_token, session)
            if is_valid then
                ngx.log(ngx.NOTICE, "User session [" .. user_session .. "] is valid.")
                return -- Allow access phase to continue
            else
                ngx.log(ngx.NOTICE, "User session[" .. user_session .. "] is NOT valid!")
                util.delete_cookie(util.cookie_key("Session"))
                util.delete_cookie(util.cookie_key("Redirect"))
            end
        end
    end

    util.set_cookies({
        util.create_cookie(util.cookie_key("Redirect"), nginx_furl, {
            ["Max-Age"] = config.cookie_lifetime,
            ["Domain"] = "." .. config.cookie_domain,
            ["Path"] = "/"
        })
    })

    ngx.redirect(lsso_login)
end
