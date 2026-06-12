local typedefs = require("kong.db.schema.typedefs")

return {
    name = "jwt-keycloak",
    fields = {
        { consumer = typedefs.no_consumer },
        { protocols = typedefs.protocols_http },
        { config = {
            type = "record",
            fields = {
                { jwks_uri = { type = "string", required = true, default = "http://keycloak:8080/realms/api-gateway-demo/protocol/openid-connect/certs" } },
                { issuer = { type = "string", required = true, default = "http://localhost:8080/realms/api-gateway-demo" } },
                { audience = { type = "string", required = false, default = "account" } },
                { cache_ttl = { type = "integer", required = false, default = 300 } },
            },
        } },
    },
}
