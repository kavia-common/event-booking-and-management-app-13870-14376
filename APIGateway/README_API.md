# API Gateway (FastAPI)

Central entry point for all client requests.

Key features:
- Authentication stub issuing development tokens (`POST /auth/token`)
- JWT extraction and RBAC dependency (`/me`, `require_roles`)
- Reverse proxy routes:
  - `/users/**` -> User Service
  - `/venues/**` -> Venue Service
  - `/bookings/**` -> Booking Service
  - `/notifications/**` -> Notification Service
- Aggregated endpoints:
  - `GET /admin/analytics/summary` (admin-only aggregation example)
  - `POST /payments/initiate` (gateway payment stub; falls back to booking if available)
  - `POST /notify` (forward to Notification Service)
- Security:
  - CORS, security headers, stub rate limiter (enable with RATE_LIMIT_PER_MINUTE)

Environment:
See `.env.example` for required variables.

Docs:
- Gateway OpenAPI: generated into `interfaces/openapi.json`
- Upstream specs copied to: `interfaces/*Service.openapi.json`
- `GET /docs/upstreams` returns paths to upstream specs.
