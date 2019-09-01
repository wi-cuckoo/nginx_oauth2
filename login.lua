local authorize_url = ngx.var.oauth_authorize_url
local client_id = ngx.var.oauth_client_id
local scope = ngx.var.oauth_scope or 'api'
local callback_url = ngx.var.oauth_callback_url
local target_uri = ngx.req.get_uri_args()['target_uri'] or '/'


local auth_url = authorize_url .. "?" .. ngx.encode_args(
  { client_id=client_id
  , scope=scope
  , response_type="code"
  , redirect_uri=callback_url
  })
ngx.log(ngx.ERR, 'Redirecting to ' .. auth_url .. ' for authorization')
ngx.redirect(auth_url)