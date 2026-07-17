"""GraphQL-lookalike route -- a plausible modern API surface for the same
Python/FastAPI backend (no tech-stack fiction needed, real GraphQL
libraries exist for Python). Detection only, no inject_payload calls.

Introspection looks enabled (a real production misconfiguration smell --
introspection is normally disabled outside dev) but the schema returned is
deliberately minimal and harmless; nothing here ever resolves a real
query."""

import re

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, PlainTextResponse

router = APIRouter()

_INTROSPECTION_PATTERN = re.compile(r"__schema|__type\b")

_FAKE_SCHEMA = {
    "__schema": {
        "queryType": {"name": "Query"},
        "types": [
            {
                "kind": "OBJECT",
                "name": "Query",
                "fields": [
                    {"name": "health", "type": {"kind": "SCALAR", "name": "String"}},
                    {"name": "version", "type": {"kind": "SCALAR", "name": "String"}},
                ],
            }
        ],
    }
}


@router.get("/graphql")
async def graphql_get():
    return PlainTextResponse("GraphQL endpoint. Use POST.", status_code=400)


@router.post("/graphql")
async def graphql_post(request: Request):
    try:
        body = await request.json()
    except ValueError:
        body = {}
    query = str(body.get("query", "")) if isinstance(body, dict) else ""

    if _INTROSPECTION_PATTERN.search(query):
        request.state.vuln_probe_detected = True
        return JSONResponse({"data": _FAKE_SCHEMA})

    if "health" in query:
        return JSONResponse({"data": {"health": "ok"}})
    if "version" in query:
        return JSONResponse({"data": {"version": "1.4.2"}})

    return JSONResponse(
        {"errors": [{"message": "Cannot query field on type 'Query'."}]},
        status_code=400,
    )
