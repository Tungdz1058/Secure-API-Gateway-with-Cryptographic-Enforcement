local cjson = require("cjson")
local resty_http = require("resty.http")
local jwt = require("resty.jwt")

local plugin_name = "jwt-keycloak"

local function fetch_jwks(jwks_uri)
    local httpc = resty_http.new()
    local res, err = httpc:request_uri(jwks_uri, { method = "GET" })
    if not res then
        return nil, "Failed to fetch JWKS: " .. err
    end
    if res.status ~= 200 then
        return nil, "JWKS endpoint returned status " .. res.status
    end
    local jwks = cjson.decode(res.body)
    return jwks, nil
end

local function get_jwk(jwks, kid)
    for _, key in ipairs(jwks.keys or {}) do
        if key.kid == kid then
            return key
        end
    end
    return nil
end

local JWTKeycloakHandler = {
    VERSION = "1.0.0",
    PRIORITY = 1000,
}

function JWTKeycloakHandler:access(conf)
    -- Lấy token từ header Authorization
    local auth_header = ngx.var.http_authorization
    if not auth_header then
        kong.response.exit(401, { message = "Missing Authorization header" })
        return
    end

    local _, _, token = string.find(auth_header, "^%s*[Bb]earer%s+(.+)$")
    if not token then
        kong.response.exit(401, { message = "Invalid Authorization header format" })
        return
    end

    -- Lấy hoặc cache JWKS
    local cache_key = "jwks:" .. conf.jwks_uri
    local jwks, err = kong.cache:get(cache_key, {
        ttl = conf.cache_ttl,
    }, function()
        return fetch_jwks(conf.jwks_uri)
    end)

    if err or not jwks then
        kong.log.err("Failed to load JWKS: ", err)
        kong.response.exit(500, { message = "Internal server error" })
        return
    end

    -- Decode JWT để lấy kid
    local jwt_obj = jwt:load_jwt(token)
    if not jwt_obj.valid then
        kong.response.exit(401, { message = "Invalid JWT" })
        return
    end

    local headers = jwt_obj.header
    if not headers or not headers.kid then
        kong.response.exit(401, { message = "Missing kid in JWT header" })
        return
    end

    local jwk = get_jwk(jwks, headers.kid)
    if not jwk then
        kong.response.exit(401, { message = "No matching JWK found" })
        return
    end

    -- Convert JWK to PEM
    local public_key = jwt.jwk_to_pem(jwk)
    if not public_key then
        kong.response.exit(500, { message = "Failed to convert JWK to PEM" })
        return
    end

    -- Verify JWT
    local verified = jwt:verify(public_key, token, {
        algorithms = { "RS256", "RS384", "RS512", "ES256" },
        issuer = conf.issuer,
        audience = conf.audience,
    })

    if not verified.verified then
        kong.log.err("JWT verification failed: ", verified.reason)
        kong.response.exit(401, { message = "Invalid token: " .. (verified.reason or "unknown") })
        return
    end

    -- Thêm thông tin user vào header để backend nhận
    local payload = verified.payload
    kong.service.request.set_header("X-User", payload.preferred_username or payload.sub)
    kong.service.request.set_header("X-Email", payload.email or "")
end

return JWTKeycloakHandler
