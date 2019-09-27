local json = require("cjson")

local cache = ngx.shared.user
local uri_args = ngx.req.get_uri_args()
local client_id = ngx.var.gitlab_client_id
local client_secret = ngx.var.gitlab_client_secret
local redirect_url = ngx.var.gitlab_redirect_url
local token_secret = ngx.var.oauth_token_secret or 'notsosecret'
local proxy_api_uri = '/_oauth/api/'
local access_token_uri = '/_oauth/access_token'
local domain = ngx.var.oauth_domain or ngx.var.host
local cookie_tail = "; Domain=" .. domain .. '; HttpOnly; Path=/'

local function exit(err)
    ngx.log(ngx.ERR, err)
    ngx.header['Content-type'] = 'text/html'
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.say(err)
    return ngx.exit(ngx.HTTP_FORBIDDEN)
end

local function check_subrequest_error(response)
    if not response then
        return "failed"
    end
    if response.status ~= 200 then
        return "failed with " .. response.status .. ": " .. response.body
    end
    return nil
end

local function request_access_token(code)
    ngx.log(ngx.ERR, 'Requesting access token with code ' .. code)
    local res = ngx.location.capture(
        access_token_uri,
        {
            method=ngx.HTTP_POST,
            args={
                client_id=client_id,
                client_secret=client_secret,
                code=code,
                grant_type="authorization_code",
                redirect_uri=redirect_url
            }
        })
    err = check_subrequest_error(res)
    if err then
        return exit("Got error during access token request: " .. err)
    else
        ngx.log(ngx.ERR, "Decoded access token request: " .. res.body)
        return json.decode(res.body)
    end
end

local function dispatch_api_request(api_uri, token)
    local api_request_uri = proxy_api_uri .. api_uri
    ngx.log(ngx.ERR, 'Making subrequest to ' .. api_request_uri .. " with token " .. token)

    ngx.req.set_header('Authorization', "Bearer " .. token)
    local api_response = ngx.location.capture(api_request_uri)
    err = check_subrequest_error(api_response)
    if err then
        return exit("Got error during request to " .. api_uri .. ": " .. err)
    end
    ngx.log(ngx.ERR, 'api response body: ' .. api_response.body)
    return json.decode(api_response.body)
end

local function profile(access_token)
    if not access_token or access_token == '' then
        return exit("No access token, fuck you")
    end

    ngx.log(ngx.ERR, "Validating access token")

    local profile = dispatch_api_request('user', access_token)
    return profile
end

local function authorize()
    if uri_args["error"] then
        return exit("received " .. uri_args["error"] .. " from OAuth provider")
    end
    if not uri_args["code"] then
        return exit("Invalid request: no code for authorization")
    end

    local response = request_access_token(uri_args["code"])
    
    local profile = profile(response["access_token"])
    local login = profile["username"]
    local token = ngx.encode_base64(ngx.hmac_sha1(token_secret, domain .. login))
    if not token then
        return exit("Failed to authenticate request")
    end

    local expiry = "; Max-Age=" .. (ngx.time() + 24*60*60)
    local cookies = {
      "OAuthLogin=" .. ngx.escape_uri(login) .. cookie_tail .. expiry,
      "OAuthAccessToken=" .. ngx.escape_uri(token) .. cookie_tail .. expiry,
    }

    -- set cache
    local uid = 0
    local ids = profile["identities"]    
    if table.getn(ids) > 0 then
        for k, item in ipairs(ids) do
            if item["provider"] == 'OA' then
                uid = tonumber(item["extern_uid"])
                break
            end
        end
    end

    local userinfo = {
        username=login,
        uid=uid,
        gid=profile["id"],
        email=profile["email"],
        avatar=profile["avatar_url"],
        nickname=profile["name"]
    }
    local succ, err, forcible = cache:set(login, json.encode(userinfo))
    if not succ then
        return exit("Fail cache user: " .. err)
    end

    ngx.header["Set-Cookie"] = cookies
    local origin = ngx.unescape_uri(ngx.var.cookie_OAuthOrigin or "/")
    ngx.log(ngx.ERR, "Redrecting to " .. origin)
    return ngx.redirect(origin)
end

authorize()
