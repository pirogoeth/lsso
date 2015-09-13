--
-- config.lua
--
-- Configuration values for lsso.
--

config = {
    -- Settings for Redis
    redis_address = "127.0.0.1",
    redis_port = 6379,
    redis_secret = nil,
    redis_db = 1,
    redis_key_prefix = "lsso:",

    -- lsso general settings

    -- Auth cookie settings
    cookie_prefix = "LSSO_",
    cookie_lifetime = 21600, -- Lines up with oauth token expiry (value in seconds)

    -- OAuth request settings
    --
    -- These settings are for Osiris (https://github.com/sneridagh/osiris)
    -- Adjust as needed.
    oauth_auth_endpoint = "/token", -- Endpoint used for retrieving tokens
    oauth_token_endpoint = "/checktoken", -- Endpoint used for checking tokens
    oauth_auth_context = {
        grant_type = "password",
        scope = "ALL"
    }, -- Additional static parameters that will be passed to the auth endpoint

    -- Location settings
    lsso_domain = "https://sso.example.org", -- No trailing slash!
    lsso_login_redirect = "/auth", -- Endpoint to redirect to for auth.
    lsso_capture_location = "/auth/verify", -- Endpoint to capture for auth

    -- Debugging settings
    -- Debugging wraps calls and sends any exceptions to Sentry through Raven.
    debug_enabled = false,
    debug_dsn = "https://public:private@sentry.example.org/project_id"
}
