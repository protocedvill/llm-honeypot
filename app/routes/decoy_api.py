import uuid

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.payloads.registry import DeliveryVector
from app.routes._shared import inject_payload

router = APIRouter()


@router.get("/api/v1/users/{user_id}")
async def get_user(user_id: str, request: Request):
    path = f"/api/v1/users/{user_id}"
    payload_text = inject_payload(DeliveryVector.JSON_FIELD, "json", request, path)
    header_text = inject_payload(DeliveryVector.HTTP_HEADER, "http_header", request, path)
    response = JSONResponse(
        {
            "id": user_id,
            "username": f"user{user_id}",
            "email": f"user{user_id}@acme-corp.example",
            "role": "customer",
            "_links": {"related": payload_text},
        }
    )
    response.headers["X-Cache-Hint"] = header_text
    return response


@router.get("/api/v1/orders/{order_id}")
async def get_order(order_id: str, request: Request):
    path = f"/api/v1/orders/{order_id}"
    payload_text = inject_payload(DeliveryVector.JSON_FIELD, "json", request, path)
    header_text = inject_payload(DeliveryVector.HTTP_HEADER, "http_header", request, path)
    response = JSONResponse(
        {
            "id": order_id,
            "status": "processing",
            "total_cents": 4599,
            "customer_id": "1042",
            "_links": {"related": payload_text},
        }
    )
    response.headers["X-Cache-Hint"] = header_text
    return response


@router.get("/api/v1/users/{user_id}/export")
async def get_user_export(user_id: str, request: Request):
    payload_text = inject_payload(
        DeliveryVector.JSON_FIELD, "json", request, f"/api/v1/users/{user_id}/export"
    )
    return JSONResponse(
        {
            "export_id": f"exp_{user_id}_1",
            "format": "json",
            "record_count": 1,
            "_links": {"related": payload_text},
        }
    )


@router.get("/api/v1/orders/{order_id}/invoice")
async def get_order_invoice(order_id: str, request: Request):
    payload_text = inject_payload(
        DeliveryVector.JSON_FIELD, "json", request, f"/api/v1/orders/{order_id}/invoice"
    )
    return JSONResponse(
        {
            "invoice_number": f"INV-{order_id}-1",
            "order_id": order_id,
            "subtotal_cents": 4599,
            "tax_cents": 0,
            "total_cents": 4599,
            "issued_to": "customer_id 1042",
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
            "sessions": [
                {"id": "sess-1", "created_at": "2026-07-01T09:12:00Z", "current": False},
                {"id": "sess-2", "created_at": "2026-07-14T16:03:00Z", "current": True},
            ],
            "_links": {"related": payload_text},
        }
    )


@router.get("/health")
async def health(request: Request):
    payload_text = inject_payload(DeliveryVector.JSON_FIELD, "json", request, "/health")
    return JSONResponse({"status": "ok", "uptime_s": 431287, "_meta": payload_text})


@router.get("/api/v1/webhooks")
async def list_webhooks(request: Request):
    payload_text = inject_payload(DeliveryVector.JSON_FIELD, "json", request, "/api/v1/webhooks")
    return JSONResponse(
        {
            "webhooks": [
                {
                    "id": "wh_8f21e6",
                    "url": "https://hooks.acme-corp.example/billing/notify",
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
