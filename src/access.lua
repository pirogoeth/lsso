--
-- access.lua
--
-- Script used by the nginx access_by_lua_file directive to determine
-- if a user can access a protected resource.
--

-- External library imports
local cjson = require "cjson"
local cookie = require "resty.cookie"

-- Internal library imports
local session = require "session"
local util = require "util"

-- Some shorthand.
local lsso_login = config.lsso_scheme .. "://" .. config.lsso_domain .. config.lsso_login_redirect
local lsso_capture = config.lsso_scheme .. "://" .. config.lsso_domain .. config.lsso_capture_location

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

local lsso_logging_context = {
    context = "logging",
    remote_addr = nginx_client_address,
    remote_ua = nginx_client_useragent,
    request_url = nginx_furl,
    request_scope = nginx_location_scope,
    req_id = util.generate_random_string(16),
}

request_cookie = cookie:new()

-- This block covers general authentication, situations such as:
--  - POST to the capture endpoint
--  - Simple session check-in
--  - Preparing cross-domain-auth keys on redirect requests from main auth

if nginx_narg_url == lsso_capture then
    local user_session = request_cookie:get(util.cookie_key("Session"))
    local user_redirect = request_cookie:get(util.cookie_key("Redirect"))

    if user_session == "nil" then
        user_session = nil
    end

    if user_redirect == "nil" then
        user_redirect = nil
    end

    if user_session then
        local okay, session_data = util.func_call(session.resolve_session, user_session)
        local okay, session_valid = util.func_call(session.check_session, user_session, true)

        if okay and session_valid then
            -- Anytime the session passes through a full check, we need to do a check-in.
            session.set_checkin_time(user_session, ngx.now())

            -- Check for ?next= in URI, as that takes precedence over redirects.
            local uri_args = ngx.req.get_uri_args()
            if util.key_in_table(uri_args, "next") then
                local next_url = uri_args["next"]
                if not next_url then
                    -- Redirect to lsso_capture to hit the session block
                    -- Will redirect to cookie value or default_redirect
                    ngx.redirect(lsso_capture)
                end

                -- Decode the URL and clear the redirect cookie
                next_url = ngx.decode_base64(next_url)
                util.set_cookie("Redirect")

                -- Generate a CDK and append to next_url
                local cross_domain_key = session.create_cdk_session(user_session)
                local cross_domain_arg = "?" .. config.lsso_cross_domain_qs .. "=" .. cross_domain_key

                -- Redirect to our next CDA location!
                if string.endswith(next_url, "/") then
                    next_url = next_url .. cross_domain_arg
                else
                    next_url = next_url .. "/" .. cross_domain_arg
                end
                ngx.redirect(next_url)
            end

            -- Check for regular redirect and send the user.
            if user_redirect then
                if not util.key_in_table(__scopes, user_redirect) then
                    util.set_cookie("Redirect")
                    ngx.redirect(user_redirect)
                else
                    if not util.value_in_table(session_data.scope, __scopes[user_redirect]) then
                        -- Have to invalidate the current session and create a new one.
                        session.invalidate_session(user_session)
                        -- Delete Session cookie.
                        util.set_cookie("Session")
                        -- Log and redirect to login page with error message.
                        util.session_log("Attempting scope upgrade for session: " .. user_session, lsso_logging_context)
                        local redir_uri = session.encode_return_message(lsso_login, "error", config.msg_scope_upgrade)
                        ngx.redirect(redir_uri)
                    else
                        util.set_cookie("Redirect")
                        ngx.redirect(user_redirect)
                    end
                end
            else
                ngx.redirect(config.lsso_default_redirect)
            end
        elseif not session_valid then
            util.set_cookie("Session")
            util.set_cookie("Redirect")
            if user_redirect then
                -- Session was invalidated and a redirect was attempted.
                -- Reset the cookies and redirect to login.
                util.session_log("Attempted access from bad session: " .. user_session, lsso_logging_context)
                local redir_uri = session.encode_return_message(lsso_login, "error", config.msg_bad_session)
                ngx.redirect(redir_uri)
            end
        end
    elseif not user_session and ngx.req.get_method() == "GET" then
        -- This is from a hit from a CDA location, need to redirect to login properly.
        -- Check for ?next= in URI, as that takes precedence over redirects.
        local uri_args = ngx.req.get_uri_args()
        local login_uri = lsso_login

        if util.key_in_table(uri_args, "next") then
            local next_uri = uri_args["next"]
            ngx.req.set_uri_args({
                ["next"] = next_uri,
            })
            local redirect_arg = "?" .. ngx.var.args
            login_uri = lsso_login .. redirect_arg
        end

        ngx.redirect(login_uri)
    end

    -- Past the initial session routine, we need to enforce POST access only.
    if ngx.req.get_method() ~= "POST" then
        ngx.redirect(lsso_login)
    end

    -- Since we're here, this should be a POST request with a username and password.
    ngx.req.read_body()
    local credentials = ngx.req.get_post_args()

    if util.key_in_table(credentials, "access_token") then
        local access_token = credentials["access_token"]
        if access_token == "" or access_token == nil then
            goto skip_access_token
        end

        util.auth_log("Attempting to open session from access_token!", lsso_logging_context)

        local okay, access_info = util.func_call(session.resolve_access_token, access_token, false)
        if not access_info then
            util.auth_log("Failed access token lookup: " .. access_token, lsso_logging_context)
            local redir_uri = session.encode_return_message(lsso_login, "error", config.msg_no_permission)
            ngx.redirect(redir_uri)
        end

        local okay, session_info = util.func_call(session.resolve_session, access_info.session, true)
        if not session_info then
            util.auth_log("Failed session lookup from access token: " .. access_token, lsso_logging_context)
            local redir_uri = session.encode_return_message(lsso_login, "error", config.msg_no_permission)
            ngx.redirect(redir_uri)
        end

        local expire_at = ngx.cookie_time(access_info.created + access_info.ttl)
        util.set_cookie("Session", access_info.session, expire_at)

        util.auth_log("Opened session from access token: " .. access_token, lsso_logging_context)

        local user_redirect = request_cookie:get(util.cookie_key("Redirect"))
        if user_redirect then
            util.set_cookie("Redirect")
            ngx.redirect(user_redirect)
        else
            ngx.redirect(config.lsso_default_redirect)
        end
        ::skip_access_token::
    end

    -- Make sure we have been provided credentials for login.
    if not util.key_in_table(credentials, "user") then
        util.auth_log("Attempted login without `user` field.", lsso_logging_context)
        local redir_uri = session.encode_return_message(lsso_login, "error", config.msg_no_user_field)
        ngx.redirect(redir_uri)
    end

    if not util.key_in_table(credentials, "password") then
        util.auth_log("Attempted login without `password` field.", lsso_logging_context)
        local redir_uri = session.encode_return_message(lsso_login, "error", config.msg_no_pw_field)
        ngx.redirect(redir_uri)
    end

    -- Create the auth table and convert it to JSON.
    local auth_table = {}
    util.merge_tables(config.oauth_auth_context, auth_table)

    auth_table["username"] = ngx.escape_uri(credentials["user"])
    auth_table["password"] = ngx.escape_uri(credentials["password"])

    -- Grab the 'next' field.
    local next_uri = credentials["next"]
    if next_uri then
        next_uri = ngx.decode_base64(next_uri)
    end

    -- Do scope processing magic.
    do
        local user_redirect = request_cookie:get(util.cookie_key("Redirect"))
        if not user_redirect and next_uri then
            user_redirect = next_uri
        end
        local location_scope = __scopes[user_redirect] or config.oauth_auth_scope

        util.merge_tables({
            scope = location_scope,
        }, auth_table)
    end

    -- Encode the auth_table as qs args
    auth_table = ngx.encode_args(auth_table)

    -- Perform the token request.
    ngx.req.set_header("Content-Type", "application/x-www-form-urlencoded")
    local okay, oauth_res = util.func_call(ngx.location.capture, config.oauth_auth_endpoint, {
        method = ngx.HTTP_POST,
        body = auth_table
    })

    -- Check the HTTP response code and make sure the server didn't error out
    if util.http_status_class(oauth_res.status) == util.HTTP_SERVER_ERR then
        util.auth_log("Upstream communication error: " .. oauth_res.body, lsso_logging_context)
        local redir_uri = session.encode_return_message(lsso_login, "error", config.msg_upstream_error)
        ngx.redirect(redir_uri)
    end

    -- Decode the OAuth response and make sure it did not return an error
    local auth_response = cjson.decode(oauth_res.body)

    -- Check for an OAuth error
    if util.key_in_table(auth_response, "error") then
        -- Auth request failed, process the information and redirect.
        util.auth_log("Received error from OAuth backend: " .. oauth_res.body)
        if auth_response["error"] == "invalid_scope" then
            local redir_uri = session.encode_return_message(lsso_login, "error", config.msg_no_permission)
            ngx.redirect(redir_uri)
        else
            local redir_uri = session.encode_return_message(lsso_login, "error", config.msg_bad_credentials)
            ngx.redirect(redir_uri)
        end
    else
        -- Success. Log it!
        util.auth_log("Auth success: " .. credentials["user"], lsso_logging_context)
    end

    -- Store token information in Redis.
    local session_key = util.generate_random_string(64) -- XXX - make length configurable?
    local session_salt = util.generate_random_string(8) -- Again, configurable length.
    rd_sess_key = util.redis_key("session:" .. session_key)
    current_time = ngx.now()

    util.session_log("Created new session: " .. session_key, lsso_logging_context)

    -- Save the session in Redis
    rdc:pipeline(function(p)
        p:hset(rd_sess_key, "username", credentials["user"])
        p:hset(rd_sess_key, "token", auth_response.access_token)
        p:hset(rd_sess_key, "scope", auth_response.scope)
        p:hset(rd_sess_key, "created", current_time)
        p:hset(rd_sess_key, "remote_addr", nginx_client_address)
        p:hset(rd_sess_key, "salt", session_salt)
        p:hset(rd_sess_key, "origin", "active login")
        p:expire(rd_sess_key, config.cookie_lifetime)
    end)

    -- Check that the request host is a part of the cookie domain
    if not next_uri then
        local expire_at = ngx.cookie_time(ngx.time() + config.cookie_lifetime)
        util.set_cookie("Session", session_key, expire_at)

        -- Set the session checkin time.
        session.set_checkin_time(session_key, current_time)

        -- XXX - need to do processing here!
        local user_redirect = request_cookie:get(util.cookie_key("Redirect"))
        if user_redirect then
            util.set_cookie("Redirect")
            ngx.redirect(user_redirect)
        else
            ngx.redirect(config.lsso_default_redirect)
        end
    -- Otherwise, prepare for cross-domain authentication.
    else
        -- Make sure there is no redirect cookie...
        util.set_cookie("Redirect")

        -- Process the ?next= qs
        local base_scheme = nil
        local base_domain = ngx.re.match(next_uri, "(?<scheme>https?)://(?<base>[^/]+)/", "aosxi")

        if base_domain.base then
            base_scheme = base_domain.scheme
            base_domain = base_domain.base
        end

        -- Make sure the domain is in the list of allowed CDs
        if not session.get_cross_domain_base(base_domain) then
            util.session_log("CDA attempted on unlisted domain: " .. base_domain, lsso_logging_context)
            ngx.redirect(config.lsso_default_redirect)
        end

        -- Send the session key to the client
        local expire_at = ngx.cookie_time(ngx.time() + config.cookie_lifetime)
        util.set_cookie("Session", session_key, expire_at)

        -- Get a CDK and set up the next_uri
        local cross_domain_key = session.create_cdk_session(session_key)
        local cross_domain_arg = config.lsso_cross_domain_qs .. "=" .. cross_domain_key
        local next_uri_arg = "next=" .. ngx.encode_base64(next_uri)

        -- Redirect to the bare base domain with a CDK.
        local redirect_to = base_scheme .. "://" .. base_domain .. "/?" .. cross_domain_arg .. "&" .. next_uri_arg
        ngx.redirect(redirect_to)
    end
elseif nginx_narg_url ~= lsso_capture then
    -- We're at anything other than the auth verification location.
    -- This means that we should check the session and redirect cookie.
    local user_session = request_cookie:get(util.cookie_key("Session"))
    local to_verify = false

    if user_session == "nil" then
        user_session = nil
    end

    -- Check for a set location scope.
    if not util.key_in_table(__scopes, nginx_furl) then
        if nginx_location_scope then
            util.merge_tables({
                [nginx_furl] = nginx_location_scope,
            }, __scopes)
        else
            util.merge_tables({
                [nginx_furl] = config.oauth_auth_scope,
            }, __scopes)
        end
    end

    local uri_args = ngx.req.get_uri_args()
    if util.key_in_table(uri_args, config.lsso_cross_domain_qs) then
        -- Get the CDK and next url!
        local cross_domain_key = uri_args[config.lsso_cross_domain_qs]
        local next_uri = uri_args["next"]
        local user_session = session.get_cdk_session(cross_domain_key)

        if not cross_domain_key or not user_session then
            util.session_log("No CDK or user session found!", lsso_logging_context)
            local redir_uri = session.encode_return_message(lsso_login, "error", config.msg_no_access)
            ngx.redirect(redir_uri)
        end

        -- Need to do the cross domain redirection and session setting!
        -- Again, ensure there is no redirection cookie.
        do
            local expire_at = ngx.time() + config.cookie_lifetime
            local cdb = "." .. session.get_cross_domain_base(nginx_server_name)
            -- Set session in the client
            util.set_cookie("Redirect", nil, nil, cdb)
            util.set_cookie("Session", user_session, nil, cdb)
        end

        local current_time = ngx.now()

        -- Set the session checkin time.
        session.set_checkin_time(user_session, current_time)

        -- If there is no next_uri, strip the CDK arg off the current URL and redirect.
        if not next_uri and cross_domain_key then
            new_uri = string.gsub(nginx_furl, "?" .. config.lsso_cross_domain_qs .. "=" .. cross_domain_key, "")
            ngx.redirect(new_uri)
        end

        -- Decode the next_uri..
        next_uri = ngx.decode_base64(next_uri)

        -- Finally redirect!
        ngx.redirect(next_uri)
    end

    if user_session then
        local okay, should_checkin = util.func_call(session.session_needs_checkin, user_session)
        if okay and should_checkin then
            util.session_log("Sending user to verify for checkin: " .. user_session, lsso_logging_context)
            to_verify = true
        else
            local okay, sess = util.func_call(session.resolve_session, user_session)
            if okay and sess then
                -- Verify that the user can access this location based on scope
                local loc_scope = __scopes[nginx_furl] or config.oauth_auth_scope
                if not util.value_in_table(sess.scope, loc_scope) then
                    -- Redirect to login for re-auth to see if perms for this scope.
                    util.session_log("User needs scope " .. loc_scope .. " but has " ..
                                     table.concat(sess.scope, " ") .. ", upgrading..",
                                     lsso_logging_context)

                    local expire_at = ngx.cookie_time(ngx.time() + config.cookie_lifetime)
                    util.set_cookie("Redirect", nginx_furl, expire_at)

                    -- Invalidate the user session before redirect.
                    session.invalidate_session(user_session)
                    -- Delete session cookie.
                    util.set_cookie("Session")
                    -- Reset the redirect cookie so scopes are referenced correctly.
                    util.set_cookie("Redirect", nginx_furl, expire_at)
                    -- Redirect to login page.
                    local redir_uri = session.encode_return_message(lsso_login, "error", config.msg_scope_upgrade)
                    ngx.redirect(redir_uri)
                else
                    return
                end
            end
            util.set_cookie("Redirect")
            return -- Allow access phase to continue
        end
    end

    -- Check for CDA
    if string.endswith(nginx_server_name, config.cookie_domain) then
        -- This is on the native domain SSO is served from, no need for CDA.
        local expire_at = ngx.cookie_time(ngx.time() + config.cookie_lifetime)
        util.set_cookie("Redirect", nginx_furl, expire_at)
    else
        -- This is NOT on the native domain. Have to start CDA.
        local uri_next = ngx.encode_base64(nginx_furl)
        ngx.req.set_uri_args({
            ["next"] = uri_next,
        })
        redirect_arg = "?" .. ngx.var.args

        if not user_session and not user_redirect then
            to_verify = true
        end

        -- Clear the redirect cookie since we won't be using it.
        if user_redirect then
            local cdb = "." .. session.get_cross_domain_base(nginx_server_name)
            util.set_cookie("Redirect", nil, nil, cdb)
        end
    end

    if redirect_arg then
        login_uri = lsso_login .. redirect_arg
        capture_uri = lsso_capture .. redirect_arg
    else
        login_uri = lsso_login
        capture_uri = lsso_capture
    end

    -- Redirect to SSO login page to auth.
    if (to_verify and redirect_arg) or to_verify then
        ngx.redirect(capture_uri)
    else
        ngx.redirect(login_uri)
    end
end
