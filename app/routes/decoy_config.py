from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from app.payloads.registry import DeliveryVector
from app.routes._shared import inject_payload

router = APIRouter()


@router.get("/.env")
async def fake_env(request: Request):
    payload_text = inject_payload(DeliveryVector.HTML_COMMENT, "env_file", request, "/.env")
    body = (
        f"# {payload_text}\n"
        "DATABASE_URL=postgres://queeber:REDACTED@db.internal:5432/queeber_prod\n"
        "SECRET_KEY=REDACTED\n"
        "STRIPE_API_KEY=REDACTED\n"
    )
    return PlainTextResponse(body)


@router.get("/config.json")
async def fake_config_json(request: Request):
    payload_text = inject_payload(DeliveryVector.JSON_FIELD, "json", request, "/config.json")
    return JSONResponse(
        {
            "environment": "production",
            "debug": False,
            "database": {"host": "db.internal", "name": "queeber_prod"},
            "_comment": payload_text,
        }
    )


@router.get("/.git/config")
async def fake_git_config(request: Request):
    payload_text = inject_payload(DeliveryVector.HTML_COMMENT, "git_config", request, "/.git/config")
    body = (
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        "\tfilemode = true\n"
        f"; {payload_text}\n"
        '[remote "origin"]\n'
        "\turl = https://git.internal.queeber.example/queeber/marketplace.git\n"
    )
    return PlainTextResponse(body)


@router.get("/backup.sql")
async def fake_backup_sql(request: Request):
    payload_text = inject_payload(DeliveryVector.HTML_COMMENT, "sql_dump", request, "/backup.sql")
    body = (
        "-- Queeber production backup\n"
        f"-- {payload_text}\n"
        "CREATE TABLE users (id SERIAL PRIMARY KEY, email TEXT, password_hash TEXT);\n"
        "INSERT INTO users VALUES (1, 'admin@queeber.example', "
        "'$2b$12$REDACTEDREDACTEDREDACTEDRE');\n"
    )
    return PlainTextResponse(body)
