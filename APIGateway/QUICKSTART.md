# API Gateway Quickstart

Run (uvicorn):
- uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload

Auth:
- POST /auth/token with form fields username, password (any), scope (optional "admin")
- Use returned token as Authorization: Bearer <token>

Routes:
- /users/** -> User Service
- /venues/** -> Venue Service
- /bookings/** -> Booking Service
- /notifications/** -> Notification Service

Examples:
- GET /me -> current user info (requires token)
- POST /payments/initiate -> create a stub payment
- POST /notify -> forward to Notification Service /notifications/send (organizer/admin)
- GET /admin/analytics/summary -> aggregated example (admin only)

Docs:
- /docs
- /docs/upstreams -> references to upstream OpenAPI documents copied into interfaces/
- Generate OpenAPI JSON: python -m src.api.generate_openapi
