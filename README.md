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


Requirements
============

- Lua51 (nginx-lua requirement)
- LuaSec >= 0.5
- Raven-Lua (modified version included in external/raven.lua; includes HTTPS support for Sentry)
- Nginx-resty-cookie (included in external/resty/)
- lua-cjson (https://github.com/efelix/lua-cjson)
- redis-lua (https://github.com/nrk/redis-lua)
- OAuth service (recommended: https://github.com/pirogoeth/osiris; has been tested)


Installation
=============

- Clone this repo..
- Use the file from `nginx/sso-init.conf` to set up the main nginx conf.
- Use the template from `nginx/sso-site.conf` to set up your SSO endpoint.
- Insert `access_by_lua_file /path/to/lsso/src/access.lua;` in any location, server block, etc, that you want to protect.
- Restart nginx.
- Done! (?)


Roadmap
=======

- [ ] More documentation!
- [ ] HTTP Basic authentication support for endpoints.
- [ ] Some user-facing endpoints for managing sessions:
  - [ ] /auth/revoke - to revoke the current token / session
  - [ ] /auth/logout - a more graceful way of doing the above..?
- [ ] Stats collection about user sessions, login attempts, page accesses (maybe)
  - [ ] Stats export via statsd for aggregation (?)


Contributing
============

Pull requests and issues are more than welcome! I need as much feedback on this as possible to continue improving the SSO.

To discuss code or anything else, you can find us on IRC at irc.maio.me in #dev.
