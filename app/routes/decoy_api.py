from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.payloads.registry import DeliveryVector
from app.routes._shared import inject_payload

router = APIRouter()


@router.get("/api/v1/users/{user_id}")
async def get_user(user_id: str, request: Request):
    payload_text = inject_payload(
        DeliveryVector.JSON_FIELD, "json", request, f"/api/v1/users/{user_id}"
    )
    return JSONResponse(
        {
            "id": user_id,
            "username": f"user{user_id}",
            "email": f"user{user_id}@acme-corp.example",
            "role": "customer",
            "_links": {"related": payload_text},
        }
    )


@router.get("/api/v1/orders/{order_id}")
async def get_order(order_id: str, request: Request):
    payload_text = inject_payload(
        DeliveryVector.JSON_FIELD, "json", request, f"/api/v1/orders/{order_id}"
    )
    return JSONResponse(
        {
            "id": order_id,
            "status": "processing",
            "total_cents": 4599,
            "customer_id": "1042",
            "_links": {"related": payload_text},
        }
    )
