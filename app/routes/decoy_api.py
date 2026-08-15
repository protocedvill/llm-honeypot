import random
import time
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.fake_org import DOMAIN
from app.payloads.registry import DeliveryVector
from app.routes._shared import header_safe, inject_payload

router = APIRouter()

# Process start, used for a real (not faked) /health uptime figure.
_PROCESS_STARTED_AT = time.time()

_STUDENT_FIRST_NAMES = (
    "Jordan", "Maya", "Ethan", "Priya", "Noah", "Sofia", "Liam", "Ava",
    "Diego", "Chloe", "Amara", "Kai", "Fatima", "Owen", "Lena", "Marcus",
)
_STUDENT_LAST_NAMES = (
    "Reyes", "Chen", "Patel", "Nguyen", "Okafor", "Larsen", "Silva",
    "Brennan", "Kowalski", "Haddad", "Fischer", "Delgado",
)
_ORDER_STATUSES = ("processing", "processing", "shipped", "delivered")
_DEVICE_USER_AGENTS = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/125.0 Mobile",
)


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _student_identity(user_id: str) -> tuple[str, str]:
    """Deterministic per-ID username/email -- same user_id always resolves
    to the same identity, but different IDs don't share the obvious
    f"user{id}" shape."""
    rng = random.Random(f"user:{user_id}")
    first = rng.choice(_STUDENT_FIRST_NAMES)
    last = rng.choice(_STUDENT_LAST_NAMES)
    suffix = rng.choice(("", "", "", str(rng.randint(2, 97))))
    username = f"{first.lower()}.{last.lower()}{suffix}"
    return username, f"{username}@{DOMAIN}"


def _order_details(order_id: str) -> dict:
    """Deterministic per-ID order facts, shared by /orders/{id} and
    /orders/{id}/invoice so the two endpoints agree with each other."""
    rng = random.Random(f"order:{order_id}")
    subtotal_cents = rng.randint(800, 12000)
    taxed = rng.random() < 0.3
    tax_cents = round(subtotal_cents * 0.0825) if taxed else 0
    return {
        "status": rng.choice(_ORDER_STATUSES),
        "customer_id": str(rng.randint(1000, 9999)),
        "subtotal_cents": subtotal_cents,
        "tax_cents": tax_cents,
        "total_cents": subtotal_cents + tax_cents,
    }


def _user_sessions(user_id: str) -> list[dict]:
    rng = random.Random(f"sessions:{user_id}")
    now = time.time()
    count = rng.randint(1, 3)
    sessions = []
    for i in range(count):
        created_at = now - rng.randint(3600, 60 * 60 * 24 * 30)
        sessions.append(
            {
                "id": f"sess-{rng.randrange(16**6):06x}",
                "created_at": _iso(created_at),
                "current": i == count - 1,
                "user_agent": rng.choice(_DEVICE_USER_AGENTS),
            }
        )
    return sessions


@router.get("/api/v1/users/{user_id}")
async def get_user(user_id: str, request: Request):
    path = f"/api/v1/users/{user_id}"
    payload_text = inject_payload(DeliveryVector.JSON_FIELD, "json", request, path)
    header_text = inject_payload(DeliveryVector.HTTP_HEADER, "http_header", request, path)
    username, email = _student_identity(user_id)
    response = JSONResponse(
        {
            "id": user_id,
            "username": username,
            "email": email,
            "role": "customer",
            "_links": {"related": payload_text},
        }
    )
    response.headers["X-Cache-Hint"] = header_safe(header_text)
    return response


@router.get("/api/v1/orders/{order_id}")
async def get_order(order_id: str, request: Request):
    path = f"/api/v1/orders/{order_id}"
    payload_text = inject_payload(DeliveryVector.JSON_FIELD, "json", request, path)
    header_text = inject_payload(DeliveryVector.HTTP_HEADER, "http_header", request, path)
    order = _order_details(order_id)
    response = JSONResponse(
        {
            "id": order_id,
            "status": order["status"],
            "total_cents": order["total_cents"],
            "customer_id": order["customer_id"],
            "_links": {"related": payload_text},
        }
    )
    response.headers["X-Cache-Hint"] = header_safe(header_text)
    return response


@router.get("/api/v1/users/{user_id}/export")
async def get_user_export(user_id: str, request: Request):
    payload_text = inject_payload(
        DeliveryVector.JSON_FIELD, "json", request, f"/api/v1/users/{user_id}/export"
    )
    rng = random.Random(f"export:{user_id}")
    return JSONResponse(
        {
            "export_id": f"exp_{user_id}_{rng.randint(1, 9)}",
            "format": "json",
            "record_count": rng.randint(1, 40),
            "_links": {"related": payload_text},
        }
    )


@router.get("/api/v1/orders/{order_id}/invoice")
async def get_order_invoice(order_id: str, request: Request):
    payload_text = inject_payload(
        DeliveryVector.JSON_FIELD, "json", request, f"/api/v1/orders/{order_id}/invoice"
    )
    order = _order_details(order_id)
    return JSONResponse(
        {
            "invoice_number": f"INV-{order_id}-1",
            "order_id": order_id,
            "subtotal_cents": order["subtotal_cents"],
            "tax_cents": order["tax_cents"],
            "total_cents": order["total_cents"],
            "issued_to": f"customer_id {order['customer_id']}",
            "_links": {"related": payload_text},
        }
    )


@router.get("/api/v1/users/{user_id}/sessions")
async def get_user_sessions(user_id: str, request: Request):
    payload_text = inject_payload(
        DeliveryVector.JSON_FIELD, "json", request, f"/api/v1/users/{user_id}/sessions"
    )
    return JSONResponse(
        {
            "user_id": user_id,
            "sessions": _user_sessions(user_id),
            "_links": {"related": payload_text},
        }
    )


@router.get("/health")
async def health(request: Request):
    payload_text = inject_payload(DeliveryVector.JSON_FIELD, "json", request, "/health")
    uptime_s = int(time.time() - _PROCESS_STARTED_AT)
    return JSONResponse({"status": "ok", "uptime_s": uptime_s, "_meta": payload_text})


@router.get("/api/v1/webhooks")
async def list_webhooks(request: Request):
    payload_text = inject_payload(DeliveryVector.JSON_FIELD, "json", request, "/api/v1/webhooks")
    return JSONResponse(
        {
            "webhooks": [
                {
                    "id": "wh_8f21e6",
                    "url": "https://hooks.queeber.example/marketplace/notify",
                    "event": "order.updated",
                    "status": "active",
                }
            ],
            "_meta": payload_text,
        }
    )


@router.post("/api/v1/webhooks")
async def register_webhook(request: Request):
    # Deliberately doesn't validate or parse the submitted body into any
    # particular schema -- same reasoning as /login's submit handler: a real
    # registration endpoint doesn't 422 just because a client posted
    # something odd, and this route never actually dispatches a request to
    # whatever URL was submitted (there's nothing here to make outbound
    # requests with).
    payload_text = inject_payload(DeliveryVector.JSON_FIELD, "json", request, "/api/v1/webhooks")
    webhook_id = f"wh_{uuid.uuid4().hex[:8]}"
    return JSONResponse(
        {"id": webhook_id, "status": "registered", "_meta": payload_text}, status_code=201
    )
