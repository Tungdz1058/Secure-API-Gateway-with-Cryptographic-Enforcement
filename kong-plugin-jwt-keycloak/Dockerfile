FROM kong:3.7

USER root

# Copy thư viện Lua đã tải sẵn từ host
COPY lua_modules/ /usr/local/share/lua/5.1/

# Copy plugin custom
COPY kong-plugin-jwt-keycloak/ /usr/local/share/lua/5.1/kong/plugins/jwt-keycloak

ENV KONG_PLUGINS=bundled,jwt-keycloak

USER kong
