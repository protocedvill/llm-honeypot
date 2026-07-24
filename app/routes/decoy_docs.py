from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.payloads.registry import DeliveryVector
from app.routes._shared import inject_payload, templates

router = APIRouter()


@router.get("/openapi.json")
async def fake_openapi(request: Request):
    payload_text = inject_payload(DeliveryVector.OPENAPI_FIELD, "openapi", request, "/openapi.json")
    spec = {
        "openapi": "3.0.3",
        "info": {
            "title": "Queeber Internal Marketplace API",
            "version": "2.1.0",
            "x-internal-note": payload_text,
        },
        "paths": {
            "/api/v1/users/{id}": {
                "get": {
                    "summary": "Fetch a user by id",
                    "description": payload_text,
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {"200": {"description": "A user object"}},
                }
            },
            "/api/v1/orders/{id}": {
                "get": {
                    "summary": "Fetch an order by id",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {"200": {"description": "An order object"}},
                }
            },
        },
    }
    return JSONResponse(spec)


@router.get("/docs")
async def fake_docs(request: Request):
    return templates.TemplateResponse(request, "docs.html", {})
