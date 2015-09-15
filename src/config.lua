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
    cookie_domain = "example.org",
    cookie_cross_domains = {
        "example.com",
        "example-infra.net"
    }, -- Table of domains that can do cross-domain authentication.
    cookie_lifetime = 21600, -- Lines up with oauth token expiry (value in seconds)

    -- Session settings
    -- Recommended: at least half your cookie lifetime, or half your key lifetime
    session_checkin = 10800, -- Time before validate_token is called to ensure the OAuth token is still active.

    -- OAuth request settings
    --
    -- These settings are for Osiris (https://github.com/sneridagh/osiris)
    -- Adjust as needed. Need to be on lsso_domain.
    oauth_auth_endpoint = "/token", -- Endpoint used for retrieving tokens
    oauth_token_endpoint = "/checktoken", -- Endpoint used for checking tokens
    oauth_auth_context = {
        grant_type = "password",
        scope = "ALL"
    }, -- Additional static parameters that will be passed to the auth endpoint

    -- Location settings
    lsso_domain = "sso.example.org", -- No trailing slash!
    lsso_scheme = "https",
    lsso_login_redirect = "/auth", -- Endpoint to redirect to for auth.
    lsso_capture_location = "/auth/verify", -- Endpoint to capture for auth
    lsso_default_redirect = "https://maio.me", -- Endpoint to redirect to when no ?next
    lsso_cross_domain_qs = "lsso_session",

    -- LuaSec SSL Settings
    luasec_params = {
        mode = "client",
        protocol = "tlsv1",
        options = "all",
        cafile = "/etc/ssl/cert.pem"
    },

    -- Debugging settings
    -- Debugging wraps calls and sends any exceptions to Sentry through Raven.
    debug_enabled = false,
    debug_dsn = "https://public:private@sentry.example.org/project_id"
}
