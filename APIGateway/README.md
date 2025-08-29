# API Gateway

FastAPI-based API Gateway for the Event Booking and Management Platform.

Features:
- JWT/OAuth2 stub authentication and RBAC
- Reverse proxy routing to backend services with path rewriting
- Aggregated endpoints (payments stub, notifications forward)
- Security headers, CORS, optional stub rate limiter
- Centralized OpenAPI generation and upstream spec collation

Run:
- uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload

Env:
- See .env.example for variables to configure.

Docs:
- /docs for Swagger UI
- Generate OpenAPI JSON: python -m src.api.generate_openapi
- /docs/upstreams returns references to upstream interfaces stored in interfaces/
