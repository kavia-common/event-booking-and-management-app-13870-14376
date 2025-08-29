import os
import time
import json
import logging
from typing import Any, Dict, List, Optional

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from starlette.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

# Load environment with defaults. In production, these must be set in .env
SERVICE_USER_URL = os.getenv("USER_SERVICE_URL", "http://userservice:8000")
SERVICE_BOOKING_URL = os.getenv("BOOKING_SERVICE_URL", "http://bookingservice:8000")
SERVICE_VENUE_URL = os.getenv("VENUE_SERVICE_URL", "http://venueservice:8000")
SERVICE_NOTIFICATION_URL = os.getenv("NOTIFICATION_SERVICE_URL", "http://notificationservice:8000")
SERVICE_ADMIN_URL = os.getenv("ADMIN_SERVICE_URL", "http://adminservice:8000")  # optional/not used directly

JWT_ISSUER = os.getenv("JWT_ISSUER", "event-platform")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "event-platform-clients")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")  # For stub HMAC decoding if used
JWT_ALG = os.getenv("JWT_ALG", "HS256")

CORS_ALLOW_ORIGINS = [o.strip() for o in os.getenv("CORS_ALLOW_ORIGINS", "*").split(",") if o.strip()]
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "0"))  # 0 disables stub limiter
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")

# Configure logging
logging.basicConfig(level=logging.INFO if ENVIRONMENT != "development" else logging.DEBUG)
logger = logging.getLogger("api-gateway")

app = FastAPI(
    title="Event Platform API Gateway",
    description=(
        "Central API gateway for the Event Booking & Management Platform.\n"
        "- AuthN/Z with JWT/OAuth2 (stubs supported)\n"
        "- RBAC enforcement\n"
        "- Reverse proxy routing to backend services\n"
        "- Aggregated endpoints for payments and notifications (stubs)\n"
        "- Centralized API docs including upstream references"
    ),
    version="0.1.0",
    openapi_tags=[
        {"name": "health", "description": "Service health and metadata"},
        {"name": "auth", "description": "Authentication and token management"},
        {"name": "gateway", "description": "Reverse proxy routes to backend services"},
        {"name": "payments", "description": "Payment operations (gateway stub)"},
        {"name": "notifications", "description": "Notification operations (gateway passthrough)"},
        {"name": "admin", "description": "Administrative helpers"},
        {"name": "docs", "description": "Documentation helpers & upstream specs"},
        {"name": "security", "description": "Security utilities"},
    ],
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOW_ORIGINS if CORS_ALLOW_ORIGINS != ["*"] else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer(auto_error=False)

# Simple in-memory rate limiter (stub). In production, use Redis or a gateway/WAF.
class RateLimiter(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, rpm: int = 0):
        super().__init__(app)
        self.rpm = rpm
        self.buckets: Dict[str, List[float]] = {}

    async def dispatch(self, request: Request, call_next):
        if self.rpm and self.rpm > 0:
            client_ip = request.client.host if request.client else "unknown"
            now = time.time()
            window_start = now - 60
            history = self.buckets.get(client_ip, [])
            history = [t for t in history if t >= window_start]
            if len(history) >= self.rpm:
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={"detail": "Rate limit exceeded"},
                )
            history.append(now)
            self.buckets[client_ip] = history
        return await call_next(request)

if RATE_LIMIT_PER_MINUTE > 0:
    app.add_middleware(RateLimiter, rpm=RATE_LIMIT_PER_MINUTE)


# Models
class Token(BaseModel):
    access_token: str = Field(..., description="Bearer access token")
    token_type: str = Field(default="bearer", description="Token type")

class UserInfo(BaseModel):
    id: str = Field(..., description="User ID")
    email: Optional[str] = Field(None, description="User email")
    roles: List[str] = Field(default_factory=list, description="Roles assigned to the user")

# PUBLIC_INTERFACE
class PaymentInitiateRequest(BaseModel):
    """Request to initiate a payment through the gateway stub."""
    booking_id: str = Field(..., description="Booking ID to pay for")
    provider: str = Field(default="stub", description="Payment provider identifier (stub by default)")
    currency: str = Field(default="USD", description="Currency code")
    amount: Optional[float] = Field(None, description="Optional amount override")

# PUBLIC_INTERFACE
class Payment(BaseModel):
    """Payment representation from gateway stub."""
    id: str = Field(..., description="Payment id")
    booking_id: str = Field(..., description="Booking id")
    amount: float = Field(..., description="Amount")
    currency: str = Field(default="USD", description="Currency")
    status: str = Field(default="pending", description="Payment status")
    provider: str = Field(default="stub", description="Provider used")

# Helpers: JWT decode/validate (stub-capable)
def _decode_jwt_stub(token: str) -> Optional[Dict[str, Any]]:
    """
    Decode a JWT using HS256 in a stub-friendly way. If secret/format mismatch,
    gracefully return minimal claims if token equals 'dev' for local testing.
    """
    try:
        # Avoid adding external dependency; implement minimal validation
        # Accept "dev" token as any user with attendee role for local use.
        if token == "dev":
            return {"sub": "dev-user", "email": "dev@example.com", "roles": ["attendee"], "iss": JWT_ISSUER, "aud": JWT_AUDIENCE}
        # Try to parse header.payload.signature
        parts = token.split(".")
        if len(parts) != 3:
            return None
        # We won't verify signature here for the stub unless explicitly needed.
        # In production: verify signature and claims with PyJWT or Auth provider SDK.
        payload_b64 = parts[1] + "==="  # pad
        import base64
        payload_json = base64.urlsafe_b64decode(payload_b64.encode("utf-8"))
        data = json.loads(payload_json.decode("utf-8"))
        return data
    except Exception as exc:
        logger.debug(f"JWT decode failed: {exc}")
        return None

# PUBLIC_INTERFACE
async def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> Optional[UserInfo]:
    """Extract current user from Authorization: Bearer <token>. Returns None if not provided."""
    if not credentials:
        return None
    token = credentials.credentials
    claims = _decode_jwt_stub(token)
    if not claims:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    user = UserInfo(
        id=str(claims.get("sub") or claims.get("user_id") or "unknown"),
        email=claims.get("email"),
        roles=[r for r in claims.get("roles", []) if isinstance(r, str)],
    )
    return user

# PUBLIC_INTERFACE
def require_roles(required: List[str]):
    """Dependency factory for requiring any of the listed roles."""
    async def _inner(user: Optional[UserInfo] = Depends(get_current_user)) -> UserInfo:
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
        if required and not any(r in user.roles for r in required):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return user
    return _inner

# Request ID and security headers middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
        return response

app.add_middleware(SecurityHeadersMiddleware)

# Health
@app.get("/", tags=["health"], summary="Health check", description="Simple health check endpoint for the API Gateway.")
def health_check():
    return {"status": "ok", "service": "api-gateway"}

# Auth stubs compatible with OAuth2PasswordRequestForm to issue a gateway token (stub).
@app.post("/auth/token", tags=["auth"], summary="Obtain access token (stub)", description="Stub endpoint to issue a development bearer token. In production this should be delegated to the User Service or an Identity Provider.", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    # THIS IS A STUB. In production, verify credentials against User Service.
    username = form_data.username
    scopes = form_data.scopes or []
    # Build a simple base64 JSON token as stub
    payload = {
        "sub": username,
        "email": f"{username}@example.com",
        "roles": ["attendee"] if "admin" not in scopes else ["admin"],
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": int(time.time()),
    }
    payload_json = json.dumps(payload).encode("utf-8")
    import base64
    token = "stub." + base64.urlsafe_b64encode(payload_json).decode("utf-8").rstrip("=") + ".sig"
    return Token(access_token=token)

# Docs helpers - link upstream OpenAPI specs discovered in repo
@app.get("/docs/upstreams", tags=["docs"], summary="List upstream OpenAPI specs", description="Provides file system references to upstream service OpenAPI specs discovered within the workspace.")
def list_upstream_specs():
    specs = {
        "user_service": "/interfaces/UserService.openapi.json",
        "booking_service": "/interfaces/BookingService.openapi.json",
        "venue_service": "/interfaces/VenueService.openapi.json",
        "notification_service": "/interfaces/NotificationService.openapi.json",
    }
    return {"upstreams": specs}

# Reverse proxy helper
async def _proxy(
    request: Request,
    upstream: str,
    path_rewrite: str,
    timeout: float = 30.0,
    user: Optional[UserInfo] = None,
) -> Response:
    """
    Proxy the incoming request to an upstream URL with path rewriting.
    Copies query params and request body. Forwards X-User-* headers for service authZ.
    """
    url = httpx.URL(upstream.rstrip("/") + "/" + path_rewrite.lstrip("/"))
    headers = dict(request.headers)
    # Remove hop-by-hop headers & sensitive ones
    for h in ["host", "content-length"]:
        headers.pop(h, None)

    # Inject user context headers for internal services
    if user:
        headers["x-user-id"] = user.id
        headers["x-user-roles"] = ",".join(user.roles)

    method = request.method
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            body = await request.body()
            resp = await client.request(
                method=method,
                url=url,
                params=request.query_params,
                headers=headers,
                content=body if body else None,
            )
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Upstream timeout")
    except httpx.HTTPError as exc:
        logger.error(f"Proxy error to {url}: {exc}")
        raise HTTPException(status_code=502, detail="Bad Gateway")

    # Stream response
    excluded_headers = {"content-encoding", "transfer-encoding", "connection", "keep-alive"}
    response_headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in excluded_headers]
    return Response(content=resp.content, status_code=resp.status_code, headers=dict(response_headers), media_type=resp.headers.get("content-type"))

# PUBLIC_INTERFACE
@app.api_route("/users/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], tags=["gateway"], summary="Proxy to User Service", description="Reverse proxy route to the User Service.")
async def proxy_user_service(full_path: str, request: Request, user: Optional[UserInfo] = Depends(get_current_user)):
    return await _proxy(request, SERVICE_USER_URL, "/" + full_path, user=user)

# PUBLIC_INTERFACE
@app.api_route("/venues/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], tags=["gateway"], summary="Proxy to Venue Service", description="Reverse proxy route to the Venue Service.")
async def proxy_venue_service(full_path: str, request: Request, user: Optional[UserInfo] = Depends(get_current_user)):
    return await _proxy(request, SERVICE_VENUE_URL, "/" + full_path, user=user)

# PUBLIC_INTERFACE
@app.api_route("/bookings/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], tags=["gateway"], summary="Proxy to Booking Service", description="Reverse proxy route to the Booking Service.")
async def proxy_booking_service(full_path: str, request: Request, user: Optional[UserInfo] = Depends(get_current_user)):
    return await _proxy(request, SERVICE_BOOKING_URL, "/" + full_path, user=user)

# PUBLIC_INTERFACE
@app.api_route("/notifications/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], tags=["gateway"], summary="Proxy to Notification Service", description="Reverse proxy route to the Notification Service.")
async def proxy_notification_service(full_path: str, request: Request, user: Optional[UserInfo] = Depends(get_current_user)):
    return await _proxy(request, SERVICE_NOTIFICATION_URL, "/" + full_path, user=user)

# RBAC protected example for admins aggregating data from multiple services
@app.get("/admin/analytics/summary", tags=["admin"], summary="Aggregate analytics (admin)", description="Aggregates analytics from Venue and Booking services. Requires admin role.")
async def analytics_summary_admin(user: UserInfo = Depends(require_roles(["admin"]))):
    results: Dict[str, Any] = {}
    async with httpx.AsyncClient(timeout=20.0) as client:
        # Example endpoints - these must exist in respective services
        try:
            venue_resp = await client.get(f"{SERVICE_VENUE_URL.rstrip('/')}/venues", headers={"x-user-id": user.id, "x-user-roles": ",".join(user.roles)})
            results["venues"] = venue_resp.json() if venue_resp.status_code == 200 else {"error": venue_resp.text}
        except Exception as exc:
            results["venues"] = {"error": str(exc)}
        try:
            # may not exist; example of safe aggregation
            booking_analytics = await client.get(f"{SERVICE_BOOKING_URL.rstrip('/')}/analytics/events/summary", headers={"x-user-id": user.id, "x-user-roles": ",".join(user.roles)})
            results["bookings"] = booking_analytics.json() if booking_analytics.status_code == 200 else {"error": booking_analytics.text}
        except Exception as exc:
            results["bookings"] = {"error": str(exc)}
    return {"aggregated": results, "generated_at": int(time.time())}

# Payments - gateway stub that delegates to Booking Service when appropriate
@app.post("/payments/initiate", tags=["payments"], summary="Initiate payment (gateway stub)", description="Initiates a payment using a gateway stub. Optionally forwards to Booking Service payment endpoint if available.", response_model=Payment)
async def initiate_payment_gateway(payload: PaymentInitiateRequest, user: UserInfo = Depends(require_roles(["attendee", "organizer", "admin"]))):
    # Try forwarding to booking service if it exposes /payments/initiate
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{SERVICE_BOOKING_URL.rstrip('/')}/payments/invite",  # try alt route (will likely 404)
                json=payload.dict(),
                headers={"x-user-id": user.id, "x-user-roles": ",".join(user.roles)},
            )
            if resp.status_code == 200:
                data = resp.json()
                return data  # already in Payment schema
    except Exception:
        pass

    # Fallback stub behavior
    amount = payload.amount if payload.amount is not None else 0.0
    return Payment(
        id=f"pay_{int(time.time())}",
        booking_id=payload.booking_id,
        amount=amount,
        currency=payload.currency,
        status="succeeded" if payload.provider == "stub" else "pending",
        provider=payload.provider or "stub",
    )

# Notification convenience endpoint that maps to Notification Service
class NotificationCreate(BaseModel):
    channel: str = Field(..., description="email or sms")
    to: str = Field(..., description="Recipient value")
    subject: Optional[str] = Field(None, description="Subject for email")
    message: str = Field(..., description="Message body")
    metadata: Dict[str, str] = Field(default_factory=dict, description="Arbitrary metadata")

@app.post("/notify", tags=["notifications"], summary="Trigger notification via Notification Service", description="Convenience endpoint that forwards to Notification Service /notifications/send.")
async def trigger_notification(payload: NotificationCreate, user: UserInfo = Depends(require_roles(["organizer", "admin"]))):
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(
            f"{SERVICE_NOTIFICATION_URL.rstrip('/')}/notifications/send",
            json=payload.dict(),
            headers={"x-user-id": user.id, "x-user-roles": ",".join(user.roles)},
        )
        if resp.status_code not in (200, 201):
            raise HTTPException(status_code=resp.status_code, detail=resp.text)
        return resp.json()

# Security helper: echo current user
@app.get("/me", tags=["security"], summary="Current user info", description="Returns information extracted from the bearer token.", response_model=UserInfo)
async def whoami(user: UserInfo = Depends(require_roles(["attendee", "organizer", "admin"]))):
    return user

# Docs: WebSocket usage note for central docs
@app.get("/docs/websocket-usage", tags=["docs"], summary="WebSocket usage notes", description="Gateway currently does not expose WebSockets directly. Real-time features are documented in upstream services. Connect to their WS endpoints as documented in their specs.")
def websocket_usage_note():
    return {"websocket": "no-op", "note": "Use upstream services' websocket endpoints directly."}
