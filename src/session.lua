--
-- session.lua - functions for validating sessions
--

module('session', package.seeall)

-- Internal library imports
local util = require "util"

-- Some shorthand.
local redis_response = nil

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

function resolve_access_token(access_token, destroy)
    -- Resolve an access token to a session token.
    local rd_acc_key = util.redis_key("acctok:" .. access_token)

    redis_response = rdc:exists(rd_acc_key)
    if not redis_response then
        return nil
    end

    redis_response = rdc:hgetall(rd_acc_key)
    if not redis_response then
        return nil
    end

    if destroy then
        rdc:del(rd_acc_key)
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

    if config.session_address_validation and session.remote_addr ~= nginx_client_address then
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

