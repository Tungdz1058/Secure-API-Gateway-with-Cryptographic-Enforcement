# Security changes applied

This version keeps the existing flow:

Vercel SPA -> FastAPI API Gateway on Render -> Auth Service/Auth0 -> Render microservices

Main fixes:

1. Removed frontend HMAC signing.
   - The SPA no longer contains HMAC_SECRET.
   - The SPA only sends the Auth0 Bearer token.

2. Fixed login order.
   - SPA calls /api/auth/login first after Auth0 callback.
   - Auth Service creates the active session during login.
   - Protected requests are verified after session exists.

3. Added internal Gateway -> Auth Service HMAC.
   - Gateway signs verification requests with INTERNAL_AUTH_SECRET.
   - Auth Service checks X-Gateway-Timestamp, X-Gateway-Nonce, X-Gateway-Signature.
   - Nonce replay protection remains in Auth Service.

4. Added internal Gateway -> Microservice HMAC.
   - Gateway signs forwarded requests with GATEWAY_SERVICE_SECRET.
   - account, transfer, and admin services verify Gateway signature using services/shared/gateway_auth.py.
   - Direct calls to public microservice URLs are rejected with 401.

Required Render environment variables:

- Gateway:
  - INTERNAL_AUTH_SECRET
  - GATEWAY_SERVICE_SECRET

- Auth Service:
  - INTERNAL_AUTH_SECRET
  - REDIS_URL optional but recommended

- Account / Transfer / Admin services:
  - GATEWAY_SERVICE_SECRET

Important: INTERNAL_AUTH_SECRET must be exactly the same in Gateway and Auth Service.
GATEWAY_SERVICE_SECRET must be exactly the same in Gateway, Account, Transfer, and Admin services.
