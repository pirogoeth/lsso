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


Requirements
============

- Lua51 (nginx-lua requirement)
- LuaSec >= 0.5
- Raven-Lua (modified version included in external/raven.lua; includes HTTPS support for Sentry)
- Nginx-resty-cookie (included in external/resty/)
- lua-cjson (https://github.com/efelix/lua-cjson)
- redis-lua (https://github.com/nrk/redis-lua)
- OAuth server (recommended: https://github.com/pirogoeth/osiris; has been tested)


Installation
=============

- Clone this repo..
- Copy external/\* to your lua5.1 package dir (/usr/local/share/lua/5.1/ or similar)
- Install [lustache](https://github.com/Olivine-Labs/lustache) to your lua5.1 package dir (see above)
- Use the file from `nginx/sso-init.conf` to set up the main nginx conf.
- Use the template from `nginx/sso-site.conf` to set up your SSO endpoint.
- Grab the src/config.lua, configure it, and stick it where you want
- Change `config_path` in src/init.lua to point to your newly configured config.lua.
- Insert `access_by_lua_file /path/to/lsso/src/access.lua;` in any location, server block, etc, that you want to protect.
- Restart nginx.
- Done! (?)


Roadmap
=======

- [ ] More documentation!
- [ ] HTTP Basic authentication support for endpoints.
- [X] Per-location auth scoping (customizable scopes for each protected location: `set $lsso_location_scope 'admin';` before `access_by_lua_file`)
- [ ] Status portal (with *content_by_lua_file* and [lustache](https://github.com/Olivine-Labs/lustache))
- [ ] Some user-facing endpoints for managing sessions:
  - [ ] /auth/logout - a more graceful way of doing the above..?
- [ ] Stats collection for info about user sessions, login attempts, page accesses (?)
  - [ ] Stats export via statsd for aggregation (?)
- [X] Log viewer endpoints (*access_by_lua_file* and *content_by_lua_file* | w/ [lustache](https://github.com/Olivine-Labs/lustache))
  - [X] /log/auth - view prettified auth event log
  - [X] /log/session - view prettified session event log
- [ ] Implement SAML 2.0 authentication
- [ ] Use JWT cookie instead of set of unsigned cookies (? | [lua-resty-jwt](https://github.com/SkyLothar/lua-resty-jwt))


Contributing
============

Pull requests and issues are more than welcome! I need as much feedback on this as possible to continue improving the SSO.

To discuss code or anything else, you can find us on IRC at irc.maio.me in #dev.


Licensing
=========

This project is licensed under the MIT License. You can view the full terms of the license in `/LICENSE.txt`.
