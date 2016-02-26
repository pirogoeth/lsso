lsso
=====

lsso is a SSO middleware written in Lua to sit between Nginx and server endpoints.

lsso uses client-side cookies alongside a Redis database of session hashes to track session.
In our setup, we use a fork of [Osiris](https://github.com/pirogoeth/osiris) with a Redis token store as an OAuth endpoint.

Features:
 - OAuth authentication
 - Raven / Sentry support
 - Cross-domain-authentication
 - Backend session store in Redis
 - Auth and session event logging to Redis
 - CLI management tool, [lssoctl](https://github.com/maiome-development/lssoctl) (*In Progress!*)
 - Management API (*In Progress!*)
 - Temporary access token generation

Requirements
============

- Lua51 (nginx-lua requirement)
- LuaSec >= 0.5
- Raven-Lua (modified version included in external/raven.lua; includes HTTPS support for Sentry)
- Nginx-resty-cookie (included in external/resty/)
- lua-cjson (https://github.com/efelix/lua-cjson)
- redis-lua (https://github.com/nrk/redis-lua)
- OAuth server (recommended: https://github.com/pirogoeth/osiris; has been tested)
- xml (https://github.com/lubyk/xml; optional, only for SAML auth)
- lzlib (luarocks: lzlib -or- src: https://github.com/LuaDist/lzlib; currently only for SAML)

Installation
=============

- Clone this repo..
- Copy external/\* to your lua5.1 package dir (/usr/local/share/lua/5.1/ or similar)
- Use the file from `nginx/sso-init.conf` to set up the main nginx conf.
  - Make sure to adjust the request rate limit to your desire.
- Use the template from `nginx/sso-site.conf` to set up your SSO endpoint.
  - Adjust any endpoints as you wish, but make sure to update `config.lua` as well.
- Grab the src/config.lua, configure it, and stick it where you want
- Change `config_path` in src/init.lua to point to your newly configured config.lua.
- Insert `access_by_lua_file /path/to/lsso/src/access.lua;` in any location, server block, etc, that you want to protect.
- Restart nginx.
- Done! (?)


Roadmap
=======

- Authentication:
  - [ ] HTTP Basic authentication support for endpoints.
    - _Stage_: Researching
  - [ ] Implement SAML 2.0 authentication
    - _Stage_: Researching & implementing
  - [ ] Implement U2F Registration / Authentication process
    - _Stage_: Researching
  - [ ] Use JWT cookie instead of set of unsigned cookies (? | [lua-resty-jwt](https://github.com/SkyLothar/lua-resty-jwt))
    - _Stage_: Researching
  - [X] Per-location auth scoping (customizable scopes for each protected location: `set $lsso_location_scope 'admin';` before `access_by_lua_file`)
- API:
  - [ ] API access tokens
    - Inherently different from regular access tokens, but possibly managed/requested through the same endpoint?
    - If using a different endpoint, possibly `/api/auth` (?).
  - [ ] Some user-facing endpoints for managing sessions:
    - [ ] /auth/logout - kill the active user session, if any.
  - [ ] API for token requests, management, health, etc.
    - [X] /api/\_health - simple status
    - [X] /api/token/request - request access token
    - [X] Log access endpoints
      - [X] /log/api - api event log
      - [X] /log/auth - authentication event log
      - [X] /log/session - session event log
      - ...
    - ...
- Miscellaneous:
  - [ ] More documentation!
  - [ ] Stats collection for info about user sessions, login attempts, page accesses (?)
    - [ ] Stats export via statsd for aggregation (?)
  - [ ] Status portal (with *content_by_lua_file* and [lustache](https://github.com/Olivine-Labs/lustache))


Contributing
============

Pull requests and issues are more than welcome! I need as much feedback on this as possible to continue improving the SSO.

To discuss code or anything else, you can find us on IRC at irc.maio.me in #dev.


Licensing
=========

This project is licensed under the MIT License. You can view the full terms of the license in `/LICENSE.txt`.
