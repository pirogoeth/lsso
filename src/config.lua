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
    session_logging = true, -- Log session messages to Redis (lsso:log:session)
    session_address_validation = true, -- Ensure a session hasn't switched IPs since last checkin.

    -- API settings
    api_logging = true, -- Log API messages to Redis (lsso:log:api)
    -- API will be exposed on lsso_scheme://lsso_domain .. api_endpoint
    api_endpoint = "/api", -- API endpoint...NO TRAILING SLASH!
    api_access_token_allowed_scopes = {
        "sso",
        "example",
        "other",
    },

    -- Auth settings
    auth_logging = true, -- Log auth messages to Redis (lsso:log:auth)

    -- OAuth request settings
    --
    -- These settings are for Osiris (https://github.com/sneridagh/osiris)
    -- Adjust as needed. Need to be on lsso_domain.
    oauth_auth_endpoint = "/token", -- Endpoint used for retrieving tokens
    oauth_token_endpoint = "/checktoken", -- Endpoint used for checking tokens
    oauth_auth_scope = "sso", -- Default scope to request for SSO access
    oauth_auth_context = { -- Additional context to send in the request to OAuth
        grant_type = "client_credentials",
    }, -- Additional static parameters that will be passed to the auth endpoint

    -- Location settings
    lsso_domain = "sso.example.org", -- Auth domain; No trailing slash!
    lsso_scheme = "https",
    lsso_login_redirect = "/auth", -- Endpoint to redirect to for auth.
    lsso_capture_location = "/auth/verify", -- Endpoint to capture for auth
    lsso_default_redirect = "https://example.org", -- Endpoint to redirect to when no ?next
    lsso_cross_domain_qs = "lsso_session",

    -- LuaSec SSL Settings; Used for raven
    luasec_params = {
        mode = "client",
        protocol = "tlsv1",
        options = "all",
        cafile = "/etc/ssl/cert.pem"
    },

    -- Auth messages
    msg_bad_credentials = "Invalid username or password.",
    msg_bad_session = "Session is invalid. Please log in again.",
    msg_no_user_field = "Missing parameter: user",
    msg_no_pw_field = "Missing parameter: password",
    msg_no_access = "Please log in to access this resource.",
    msg_no_permission = "You do not have permission to access this resource.",
    msg_scope_upgrade = "Please log in again to upgrade your access.",
    msg_error = "Something happened while processing request data. Clear your cookies and try again.",
    msg_upstream_error = "Could not communicate with upstream...Try again later.",

    -- Debugging settings
    -- Debugging wraps calls and sends any exceptions to Sentry through Raven.
    debug_enabled = false,
    debug_dsn = "https://public:private@sentry.example.org/project_id"
}
