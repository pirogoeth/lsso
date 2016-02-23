API Endpoint Docs & Roadmap
===========================

#### Implementation
The LSSO API is implemented as a separate Lua source file in the `src` directory. 
For now, endpoints are simply matched without any crazy routing handler, although that would be a nice way to go in the future. 

So far, there are three API endpoints exposed:
 - `/_health`
 - `/token/request`
 - `/log/:bucket`

##### `/_health`
The `/_health` API endpoint serves a simple purpose: to return the string `"okay"`.
This endpoint *does not* require authentication.

##### `/token/request`
The `/token/request` endpoint allows a user to programmatically request an SSO access token, which can then be used by an external user to obtain a delegated session token for protected site access. This can possibly be a security vulnerability if the access token enters the wrong hands, but some precautions are taken to ensure that damage is limited:
 - Tokens only live for the number of hours specified by `config.cookie_lifetime`, at maximum.
 - Once a token is used to retrieve a delegated session, the token itself is destroyed and the session is sent to the requesting user.
 - Access tokens can be scoped manually, unlike regular requests, which may compound scopes as escalation is needed. This way, the delegated user has access to only scopes the delegating user provides. Because of the token lifetime, if a scope elevation point is reached, the access token will not be able to be re-used to authenticate and normal authentication will be required.

Endpoint Details:
  
  HTTP Method: `POST`
  
  Parameters:
  - `username` -> OAuth Username to identify as
  - `password` -> OAuth Password for above username
  - `expire` -> Seconds until expiry (optional; defaults to `config.cookie_lifetime`)
  - `scope` -> Space-separated list of scopes to assign to the token (optional; defaults to `config.oauth_auth_scope`)
  
  Returns:
  - JSON Dictionary indicating status, errors, and response data:
      
    Failure:
    
    ```
      {
      	"code": 400,
      	"message": "Missing `username` field"
      }
    ```
    
    Success:
    
    ```
      {
      	"code": 200,
      	"message": "Access token created",
      	"token": "<access token>",
      	"expires": "<unix timestamp>",
      	"username": "<delegating username>"
      }
    ```
    
  Return Codes:
  
  Codes are returned through the `code` field on the JSON response. There are several possible values, each with a more detailed error message.
  
  `.code = 400`:
  - Missing `username` or `password` field
  
  `.code = 200`:
  - Access token created successfully.
  
  `.code = *`:
  - Any other code comes from the upstream OAuth server when an error occurs.

##### `/log/:bucket`
The `/log/:bucket` endpoint allows an administrator to dump logs from the Redis backend via a remote call. By default, there is no authentication enforcement imposed on this endpoint, so it is recommended that it be protected (as is demonstrated in `nginx/sso-site.conf`) by some authentication. Available log buckets are `api`, `auth`, and `session`

**NOTE**: Should you choose to guard the logging endpoint with LSSO itself, know that there is no HTTP basic authentication support in the codebase yet, so this endpoint would only be realistically usable from a browser.

Endpoint Details:
  
  HTTP Method: `GET`
  
  Parameters:
  - `:bucket:` - [URI] - Must be one of ("api" "auth" "session")
  - `page` - [QS] - Useful for pagination.
  - `limit` - [QS] - Number of items to show per-page (optional; defaults to `config.log_paginate_count`)
  
  Returns:
  
  - JSON dictionary with status, pagination info, and response data.
  
    Failure:
    
    ```
      {
      	"code": 404,
      	"message": "Requested log bucket does not exist."
      }
    ```
    
    Success:
    
    ```
      {
      	"code": 200,
      	"message": "okay",
      	"pagination": {
           	"page": 0,
           	"limit": 20
           },
           "response": [...]
      }
    ```
  
  Return Values:
  
  `.code = 404`:
  - Log bucket was not found.
  
  `.code = 200`:
  - Log bucket was found and fetched.
