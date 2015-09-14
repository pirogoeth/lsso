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

function should_redirect_verify(user_session)
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
        return true
    else
        return false
    end
end

function check_session(user_session)
    -- Take a user's session key and use it to validate the session.
    ngx.log(ngx.NOTICE, "Checking existing user session: " .. user_session)
    local okay, session = util.func_call(resolve_session, user_session)
    if not okay or not session then
        return false
    end

    local _, last_checkin = util.func_call(get_checkin_time, user_session)
    if not last_checkin then
        last_checkin = session.created
    end

    if okay and session then
        if ((last_checkin + config.session_checkin) < ngx.now()) then
            local okay, is_valid = util.func_call(validate_token, session)
            if is_valid then
                ngx.log(ngx.NOTICE, "User session [" .. user_session .. "] is valid.")
                return true
            else
                ngx.log(ngx.NOTICE, "User session[" .. user_session .. "] is NOT valid!")
                return false
            end
        else
            -- Have not hit the checkin time yet.
            local okay, set_success = util.func_call(set_checkin_time, user_session, ngx.now())
            if not okay or not set_success then
                ngx.log(ngx.NOTICE, "Could not set checkin time: " .. user_session)
            end
            ngx.log(ngx.NOTICE, "User session [" .. user_session .. "] has resolved, passing")
            return true
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

if nginx_furl == lsso_capture then
    if ngx.req.get_method() ~= "POST" then
        ngx.redirect(lsso_login)
    end

    user_session = util.get_cookie(util.cookie_key("Session"))
    if user_session then
        local okay, session_valid = util.func_call(check_session, user_session)
        if okay and session_valid then
            user_redirect = util.get_cookie(util.cookie_key("Redirect"))
            if user_redirect then
                util.delete_cookie(util.cookie_key("Redirect"))
                ngx.redirect(user_redirect)
            else
                ngx.redirect(config.lsso_default_redirect)
            end
        elseif not session_valid then
            util.delete_cookie(util.cookie_key("Session"))
            util.delete_cookie(util.cookie_key("Redirect"))
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
    local session_key = util.generate_random_string(64) -- XXX - make length configurable?
    local rd_sess_key = util.redis_key("session:" .. session_key)

    util.set_cookies({
        util.create_cookie(util.cookie_key("Session"), session_key, {
            ["Path"] = "/",
            ["Domain"] = "." .. config.cookie_domain,
            ["Max-Age"] = config.cookie_lifetime
        })
    })

    local current_time = ngx.now()

    rdc:pipeline(function(p)
        p:hset(rd_sess_key, "username", credentials["user"])
        p:hset(rd_sess_key, "token", auth_response.access_token)
        p:hset(rd_sess_key, "created", current_time)
        p:hset(rd_sess_key, "remote_addr", nginx_client_address)
        p:expire(rd_sess_key, config.cookie_lifetime)
    end)

    set_checkin_time(session_key, current_time)

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
    -- This means that we should check the session and redirect cookie.
    local user_session = util.get_cookie(util.cookie_key("Session"))
    local to_verify = false
    if user_session then
        local okay, session_valid = util.func_call(check_session, user_session)
        if okay and session_valid then
            local okay, should_checkin = util.func_call(should_redirect_verify, user_session)
            if okay and should_checkin then
                -- XXX - redirect back to the capture location for verification
                to_verify = true
            else
                return -- Allow access phase to continue
            end
        elseif not session_valid then
            util.delete_cookie(util.cookie_key("Session"))
            util.delete_cookie(util.cookie_key("Redirect"))
        end
    end

    util.set_cookies({
        util.create_cookie(util.cookie_key("Redirect"), nginx_furl, {
            ["Max-Age"] = config.cookie_lifetime,
            ["Domain"] = "." .. config.cookie_domain,
            ["Path"] = "/"
        })
    })

    -- Redirect to SSO login page to auth.
    if to_verify then
        ngx.redirect(lsso_capture_location)
    else
        ngx.redirect(lsso_login)
    end
end
