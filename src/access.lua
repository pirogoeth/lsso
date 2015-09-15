--
-- access.lua
--
-- Script used by the nginx access_by_lua_file directive to determine
-- if a user can access a protected resource.
--

-- External library imports
local cjson = require "cjson"
local cookie = require "resty.cookie"
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
nginx_client_useragent = ngx.req.get_headers()["User-Agent"]

request_cookie = cookie:new()

-- Functions for session validation.
function resolve_session(session_token)
    -- Resolve a session token to an auth token.
    local rd_sess_key = util.redis_key("session:" .. session_token)

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

function session_needs_checkin(user_session)
    -- Returns whether or not we should redirect to the auth endpoint
    -- to validate a users session. This solves intra-domain verification issues.
    local okay, session = util.func_call(resolve_session, user_session)
    if not okay or not session then
        return true
    end

    local _, last_checkin = util.func_call(get_checkin_time, user_session)
    if not last_checkin then
        last_checkin = session.created
        set_checkin_time(user_session, last_checkin)
    end

    local checkin_time = last_checkin + config.session_checkin
    local current_time = ngx.now()

    if current_time > checkin_time then
        ngx.log(ngx.NOTICE, "Session " .. user_session .. " is past checkin time")
        return true
    else
        return false
    end
end

function check_session(user_session, do_validate)
    -- Take a user's session key and use it to validate the session.
    ngx.log(ngx.NOTICE, "Checking existing user session: " .. user_session)
    local okay, session = util.func_call(resolve_session, user_session)
    if not okay or not session then
        return false
    end

    if session.remote_addr ~= nginx_client_address then
        -- We need to invalidate this session, it may have been compromised.
        local okay = util.func_call(invalidate_session, user_session)
        if not okay then
            ngx.log(ngx.WARNING, "Could not invalidate user session!")
            return false
        end
        -- Essentially, this session is no longer valid.
        return false
    end

    if okay and session and do_validate then
        local okay, is_valid = util.func_call(validate_token, session)
        if is_valid then
            ngx.log(ngx.NOTICE, "User session [" .. user_session .. "] is valid.")
            return true
        else
            ngx.log(ngx.NOTICE, "User session[" .. user_session .. "] is NOT valid!")
            return false
        end
    end

    return false
end

function get_checkin_time(user_session)
    local rd_checkin_key = util.redis_key("checkin:" .. user_session)

    redis_response = rdc:exists(rd_checkin_key)
    if not redis_response then
        ngx.log(ngx.NOTICE, "User session [" .. user_session .. "] has no session checkin time!")
        return nil
    end

    redis_response = rdc:get(rd_checkin_key)
    if not redis_response then
        ngx.log(ngx.NOTICE, "User session [" .. user_session .. "] has no session checkin time!")
        return nil
    end

    return redis_response
end

function set_checkin_time(user_session, time_secs)
    local rd_checkin_key = util.redis_key("checkin:" .. user_session)

    local prev_time = get_checkin_time(user_session)
    if prev_time then
        ngx.log(ngx.DEBUG, "Updating session (" .. user_session .. ") checkin time to " .. time_secs .. " from " .. prev_time)
    end

    redis_response = rdc:set(rd_checkin_key, time_secs)
    if not redis_response then
        ngx.log(ngx.NOTICE, "Setting checkin time failed!")
        return false
    end

    return true
end

function invalidate_session(user_session)
    local rd_session_key = util.redis_key("session:" .. user_session)
    local rd_checkin_key = util.redis_key("checkin:" .. user_session)

    rdc:pipeline(function(p)
        p:del(rd_session_key)
        p:del(rd_checkin_key)
    end)
end

if nginx_furl == lsso_capture then
    local user_session = request_cookie:get(util.cookie_key("Session"))
    local user_redirect = request_cookie:get(util.cookie_key("Redirect"))
    if user_session then
        local okay, session_valid = util.func_call(check_session, user_session, true)
        if okay and session_valid then
            -- Anytime the session passes through a full check, we need to do a check-in.
            set_checkin_time(user_session, ngx.now())
            -- Check for redirect and do so.
            if user_redirect then
                ngx.log(ngx.NOTICE, "User redirect: " .. user_redirect)
                request_cookie:set({
                    key = util.cookie_key("Redirect"),
                    value = "" })
                ngx.redirect(user_redirect)
            else
                ngx.redirect(config.lsso_default_redirect)
            end
        elseif not session_valid then
            request_cookie:set({
                key = util.cookie_key("Session"),
                value = "",
                max_age = util.COOKIE_EXPIRY })
            request_cookie:set({
                key = util.cookie_key("Redirect"),
                value = "",
                max_age = util.COOKIE_EXPIRY })
            if user_redirect then
                -- Session was invalidated and a redirect was attempted.
                -- Reset the cookies and redirect to login.
                ngx.redirect(lsso_login)
            end
        end
    end

    -- Past the initial session routine, we need to enforce POST access only.
    if ngx.req.get_method() ~= "POST" then
        ngx.redirect(lsso_login)
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
    local session_key = util.generate_random_string(64) -- XXX - make length configurable?
    local session_salt = util.generate_random_string(8) -- Again, configurable length.
    local rd_sess_key = util.redis_key("session:" .. session_key)

    ngx.log(ngx.NOTICE, "Sending session to client...")

    request_cookie:set({
        key = util.cookie_key("Session"), 
        value = session_key,
        path = "/",
        domain = "." .. config.cookie_domain,
        max_age = config.cookie_lifetime })

    local current_time = ngx.now()

    -- Save the session in Redis
    rdc:pipeline(function(p)
        p:hset(rd_sess_key, "username", credentials["user"])
        p:hset(rd_sess_key, "token", auth_response.access_token)
        p:hset(rd_sess_key, "created", current_time)
        p:hset(rd_sess_key, "remote_addr", nginx_client_address)
        p:hset(rd_sess_key, "salt", session_salt)
        p:expire(rd_sess_key, config.cookie_lifetime)
    end)

    -- Set the session checkin time.
    set_checkin_time(session_key, current_time)

    -- XXX - need to do processing here!
    user_redirect = request_cookie:get(util.cookie_key("Redirect"))
    if user_redirect then
        request_cookie:set({
            key = util.cookie_key("Redirect"),
            value = "",
            max_age = util.COOKIE_EXPIRY })
        ngx.redirect(user_redirect)
    else
        ngx.redirect(config.lsso_default_redirect)
    end
elseif nginx_uri ~= lsso_capture then
    -- We're at anything other than the auth verification location.
    -- This means that we should check the session and redirect cookie.
    local user_session = request_cookie:get(util.cookie_key("Session"))
    local to_verify = false
    ngx.log(ngx.NOTICE, "Checking session for redirection to " .. nginx_uri)
    if user_session then
        local okay, should_checkin = util.func_call(session_needs_checkin, user_session)
        if okay and should_checkin then
            -- XXX - redirect back to the capture location for verification
            ngx.log(ngx.NOTICE, "Falling back to VERIFICATION for token check.")
            to_verify = true
        else
            ngx.log(ngx.NOTICE, "Falling back to access phase.")
            request_cookie:set({
                key = util.cookie_key("Redirect"),
                value = "",
                max_age = util.COOKIE_EXPIRY })
            return -- Allow access phase to continue
        end
    end

    request_cookie:set({
        key = util.cookie_key("Redirect"),
        value = nginx_furl,
        max_age = config.cookie_lifetime,
        domain = "." .. config.cookie_domain,
        path = "/" })

    -- Redirect to SSO login page to auth.
    if to_verify then
        ngx.log(ngx.NOTICE, "Redirect to capture location for verification: " .. user_session .. " ~> " .. nginx_uri)
        ngx.redirect(lsso_capture)
    else
        ngx.redirect(lsso_login)
    end
end
