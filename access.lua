local domain = ngx.var.oauth_domain or ngx.var.host
local token_secret = ngx.var.oauth_token_secret or 'notsosecret'
local login_uri = '/_oauth/login'

local function is_authorized()
    local login = ngx.unescape_uri(ngx.var.cookie_OAuthLogin)
    local token = ngx.unescape_uri(ngx.var.cookie_OAuthAccessToken)
    ngx.log(ngx.ERR, "Checking authorization of " .. login .. " with token " .. token)

    if login == '' or token == '' then
        ngx.log(ngx.ERR, "Missing auth cookies")
        return false
    end

    local expected_token = ngx.encode_base64(ngx.hmac_sha1(token_secret, domain .. login))
    ngx.log(ngx.ERR, "Checking " .. login .. "'s token, " .. (token or 'nil') .. ", against expected token, " .. expected_token)
    if token ~= expected_token then
        ngx.log(ngx.ERR, "User " .. login .. " has a bad token")
        return false
    end

    ngx.log(ngx.ERR, login .. " is authorized")
    return true
end

local function target_url()
    return ngx.var.scheme .. '://' .. ngx.var.host .. ngx.var.request_uri
end

local function redirect_to_login(target_uri)
    local login_args = { target_uri=target_uri or '/' }
    local encoded_login_args = ngx.encode_args(login_args)
    -- i.e. http://my_oauth_url/_oauth/login?target_uri=/
    local login_uri_with_args = login_uri .. '?' .. encoded_login_args
    ngx.log(ngx.ERR, "Redirecting to " .. login_uri_with_args)
    ngx.redirect(login_uri_with_args)
end

if not is_authorized() then
    redirect_to_login(target_url())
end