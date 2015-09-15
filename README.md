lsso
=====

lsso is a SSO middleware written in Lua to sit between Nginx and server endpoints.

lsso uses client-side cookies alongside a Redis database of session hashes to track session.
In our setup, we use a fork of [Osiris](https://github.com/pirogoeth/osiris) with a Redis backend as an OAuth endpoint.

Features:
 - OAuth authentication
 - Raven / Sentry support
 - Cross-domain-authentication

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
- etc
