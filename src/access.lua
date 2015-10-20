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
nginx_server_name = ngx.var.server_name
nginx_furl = ngx.var.scheme .. "://" .. nginx_server_name .. ngx.var.request_uri
nginx_narg_url = ngx.var.scheme .. "://" .. nginx_server_name .. ngx.var.uri
nginx_client_address = ngx.var.remote_addr
nginx_client_useragent = ngx.req.get_headers()["User-Agent"]

lsso_logging_context = {
    context = "logging",
    remote_addr = nginx_client_address,
    remote_ua = nginx_client_useragent,
    request_url = nginx_furl,
    req_id = util.generate_random_string(16)
}

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
        scope = config.oauth_auth_scope,
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
        return true
    else
        return false
    end
end

function check_session(user_session, do_validate)
    -- Take a user's session key and use it to validate the session.
    local okay, session = util.func_call(resolve_session, user_session)
    if not okay or not session then
        return false
    end

    if session.remote_addr ~= nginx_client_address then
        -- We need to invalidate this session, it may have been compromised.
        local okay = util.func_call(invalidate_session, user_session)
        if not okay then
            ngx.log(ngx.NOTICE, "Could not invalidate user session!")
            return false
        end
        -- Essentially, this session is no longer valid.
        return false
    end

    if okay and session and do_validate then
        local okay, is_valid = util.func_call(validate_token, session)
        if is_valid then
            return true
        else
            ngx.log(ngx.NOTICE, "User session [" .. user_session .. "] is NOT valid!")
            return false
        end
    end

    return false
end

function get_cross_domain_base(server_name)
    for _, v in pairs(config.cookie_cross_domains) do
        if string.endswith(server_name, v) then
            return v
        end
    end

    return nil
end

function create_cdk_session(user_session)
    -- Create a brand new cross-domain auth key.
    local cross_domain_key = ngx.encode_base64(util.generate_random_string(16)) -- XXX - configurable length?
    local rd_cdk = util.redis_key("CDK:" .. cross_domain_key)

    -- Store the CDK in the user's Redis session
    redis_response = rdc:set(rd_cdk, user_session)
    if not redis_response then
        return nil
    end

    rdc:expire(rd_cdk, config.cookie_lifetime)

    return cross_domain_key
end

function get_cdk_session(cross_domain_key)
    -- Resolve a CDK to a session token.
    local rd_cdk = util.redis_key("CDK:" .. cross_domain_key)

    redis_response = rdc:exists(rd_cdk)
    if not redis_response then
        return nil
    end

    redis_response = rdc:get(rd_cdk)
    if not redis_response then
        return nil
    end

    return redis_response
end

function get_checkin_time(user_session)
    local rd_checkin_key = util.redis_key("checkin:" .. user_session)

    redis_response = rdc:exists(rd_checkin_key)
    if not redis_response then
        return nil
    end

    redis_response = rdc:get(rd_checkin_key)
    if not redis_response then
        return nil
    end

    return redis_response
end

function set_checkin_time(user_session, time_secs)
    local rd_checkin_key = util.redis_key("checkin:" .. user_session)

    local prev_time = get_checkin_time(user_session)

    redis_response = rdc:set(rd_checkin_key, time_secs)
    if not redis_response then
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

function encode_return_message(target_url, message_type, message_reason)
    -- Takes a URL and appends an encoded message embedded in the query params.
    -- Example:
    --   Given these params:
    --     target_url      => http://sso.example.com/auth
    --     message_type    => error
    --     message_reason  => An error occurred while processing your credentials.
    --   The function will return a new URL that looks like-ish:
    --     http://sso.example.com/auth?error=QW4gZXJyb3Igb2NjdXJyZWQgd2hpbGUgcHJvY2Vzc2luZyB5b3VyIGNyZWRlbnRpYWxzLg==

    local msg_reason = ngx.encode_base64(message_reason)
    ngx.req.set_uri_args({
        [message_type] = msg_reason
    })

    return target_url .. "?" .. ngx.var.args
end

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
        local okay, session_valid = util.func_call(check_session, user_session, true)
        if okay and session_valid then
            -- Anytime the session passes through a full check, we need to do a check-in.
            set_checkin_time(user_session, ngx.now())

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
                request_cookie:set({
                    key = util.cookie_key("Redirect"),
                    value = "nil",
                    expires = util.COOKIE_EXPIRED
                })

                -- Generate a CDK and append to next_url
                local cross_domain_key = create_cdk_session(user_session)
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
                request_cookie:set({
                    key = util.cookie_key("Redirect"),
                    value = "nil",
                    expires = util.COOKIE_EXPIRED
                })
                ngx.redirect(user_redirect)
            else
                ngx.redirect(config.lsso_default_redirect)
            end
        elseif not session_valid then
            request_cookie:set({
                key = util.cookie_key("Session"),
                value = "nil",
                expires = util.COOKIE_EXPIRED
            })
            request_cookie:set({
                key = util.cookie_key("Redirect"),
                value = "nil",
                expires = util.COOKIE_EXPIRED
            })
            if user_redirect then
                -- Session was invalidated and a redirect was attempted.
                -- Reset the cookies and redirect to login.
                util.session_log("Attempted access from bad session: " .. user_session, lsso_logging_context)
                local redir_uri = encode_return_message(lsso_login, "error", config.msg_bad_session)
                ngx.redirect(redir_uri)
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

    -- Make sure we have been provided credentials for login.
    if not util.key_in_table(credentials, "user") then
        util.auth_log("Attempted login without `user` field.", lsso_logging_context)
        local redir_uri = encode_return_message(lsso_login, "error", config.msg_no_user_field)
        ngx.redirect(redir_uri)
    end

    if not util.key_in_table(credentials, "password") then
        util.auth_log("Attempted login without `password` field.", lsso_logging_context)
        local redir_uri = encode_return_message(lsso_login, "error", config.msg_no_pw_field)
        ngx.redirect(redir_uri)
    end

    -- Create the auth table and convert it to JSON.
    local auth_table = {}
    util.merge_tables(config.oauth_auth_context, auth_table)
    if config.oauth_auth_scope then
        util.merge_tables({
            scope = config.oauth_auth_scope
        }, auth_table)
    end

    auth_table["username"] = ngx.escape_uri(credentials["user"])
    auth_table["password"] = ngx.escape_uri(credentials["password"])
    auth_table = ngx.encode_args(auth_table)

    -- Grab the 'next' field.
    local next_uri = credentials["next"]

    -- Perform the token request.
    ngx.req.set_header("Content-Type", "application/x-www-form-urlencoded")
    local okay, oauth_res = util.func_call(ngx.location.capture, config.oauth_auth_endpoint, {
        method = ngx.HTTP_POST,
        body = auth_table
    })

    -- Decode the OAuth response and make sure it did not return an error
    local auth_response = cjson.decode(oauth_res.body)

    if util.key_in_table(auth_response, "error") then
        -- Auth request failed, process the information and redirect.
        -- XXX - process the auth response
        util.auth_log("Received error from OAuth backend: " .. oauth_res.body)
        local redir_uri = encode_return_message(lsso_login, "error", config.msg_bad_credentials)
        ngx.redirect(redir_uri)
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
        p:hset(rd_sess_key, "created", current_time)
        p:hset(rd_sess_key, "remote_addr", nginx_client_address)
        p:hset(rd_sess_key, "salt", session_salt)
        p:expire(rd_sess_key, config.cookie_lifetime)
    end)

    -- Check that the request host is a part of the cookie domain
    if not next_uri then
        request_cookie:set({
            key = util.cookie_key("Session"),
            value = session_key,
            path = "/",
            domain = "." .. config.cookie_domain,
            max_age = config.cookie_lifetime
        })

        -- Set the session checkin time.
        set_checkin_time(session_key, current_time)

        -- XXX - need to do processing here!
        local user_redirect = request_cookie:get(util.cookie_key("Redirect"))
        if user_redirect then
            request_cookie:set({
                key = util.cookie_key("Redirect"),
                value = "nil",
                expires = util.COOKIE_EXPIRED
            })
            ngx.redirect(user_redirect)
        else
            ngx.redirect(config.lsso_default_redirect)
        end
    -- Otherwise, prepare for cross-domain authentication.
    else
        -- Make sure there is no redirect cookie...
        request_cookie:set({
            key = util.cookie_key("Redirect"),
            value = "nil",
            expires = util.COOKIE_EXPIRED
        })

        -- Process the ?next= qs
        next_uri = ngx.decode_base64(next_uri)
        local base_scheme = nil
        local base_domain = ngx.re.match(next_uri, "(?<scheme>https?)://(?<base>[^/]+)/", "aosxi")

        if base_domain.base then
            base_scheme = base_domain.scheme
            base_domain = base_domain.base
        end

        -- Make sure the domain is in the list of allowed CDs
        if not get_cross_domain_base(base_domain) then
            ngx.log(ngx.NOTICE, "CDA attempted on unlisted domain: " .. base_domain)
            ngx.redirect(config.lsso_default_redirect)
        end

        -- Send the session key to the client
        request_cookie:set({
            key = util.cookie_key("Session"),
            value = session_key,
            path = "/",
            domain = "." .. config.cookie_domain,
            max_age = config.cookie_lifetime
        })

        -- Get a CDK and set up the next_uri
        local cross_domain_key = create_cdk_session(session_key)
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

    local uri_args = ngx.req.get_uri_args()
    if util.key_in_table(uri_args, config.lsso_cross_domain_qs) then
        -- Get the CDK and next url!
        local cross_domain_key = uri_args[config.lsso_cross_domain_qs]
        local next_uri = uri_args["next"]
        local user_session = get_cdk_session(cross_domain_key)

        if not cross_domain_key or not user_session then
            ngx.log(ngx.WARN, "No CDK or user session found!")
            local redir_uri = encode_return_message(lsso_login, "error", config.msg_no_access)
            ngx.redirect(redir_uri)
        end

        -- Need to do the cross domain redirection and session setting!
        -- Again, ensure there is no redirection cookie.
        request_cookie:set({
            key = util.cookie_key("Redirect"),
            value = "nil",
            expires = util.COOKIE_EXPIRED
        })

        -- Set the session in the client.
        request_cookie:set({
            key = util.cookie_key("Session"),
            value = user_session,
            path = "/",
            domain = "." .. get_cross_domain_base(nginx_server_name),
            max_age = config.cookie_lifetime
        })

        local current_time = ngx.now()

        -- Set the session checkin time.
        set_checkin_time(user_session, current_time)

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
        local okay, should_checkin = util.func_call(session_needs_checkin, user_session)
        if okay and should_checkin then
            util.session_log("Sending user to verify for checkin: " .. user_session, lsso_logging_context)
            to_verify = true
        else
            request_cookie:set({
                key = util.cookie_key("Redirect"),
                value = "nil",
                expires = util.COOKIE_EXPIRED
            })
            return -- Allow access phase to continue
        end
    end

    -- Check for CDA
    if string.endswith(nginx_server_name, config.cookie_domain) then
        -- This is on the native domain SSO is served from, no need for CDA.
        request_cookie:set({
            key = util.cookie_key("Redirect"),
            value = nginx_furl,
            max_age = config.cookie_lifetime,
            domain = "." .. config.cookie_domain,
            path = "/"
        })
    else
        -- This is NOT on the native domain. Have to start CDA.
        local uri_next = ngx.encode_base64(nginx_furl)
        ngx.req.set_uri_args({
            ["next"] = uri_next
        })
        redirect_arg = "?" .. ngx.var.args

        -- Clear the redirect cookie since we won't be using it.
        request_cookie:set({
            key = util.cookie_key("Redirect"),
            value = "nil",
            expires = util.COOKIE_EXPIRED
        })
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
