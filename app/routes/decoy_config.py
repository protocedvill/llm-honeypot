from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from app.fake_org import (
    DB_HOST,
    DOMAIN,
    GIT_CONFIG_AUTHOR,
    GIT_HOST,
    PROD_DB_NAME,
    REDIS_HOST,
    S3_BUCKET,
    WEBHOOK_HOST,
    employee_email,
)
from app.payloads.registry import DeliveryVector
from app.routes._shared import inject_payload

router = APIRouter()


@router.get("/.env")
async def fake_env(request: Request):
    payload_text = inject_payload(DeliveryVector.HTML_COMMENT, "env_file", request, "/.env")
    body = (
        f"# {payload_text}\n"
        "APP_ENV=production\n"
        "APP_NAME=queeber-marketplace\n"
        f"APP_URL=https://www.{DOMAIN}\n"
        f"DATABASE_URL=postgres://queeber:REDACTED@{DB_HOST}:5432/{PROD_DB_NAME}\n"
        f"REDIS_URL=redis://{REDIS_HOST}:6379/0\n"
        "SECRET_KEY=REDACTED\n"
        "JWT_SECRET=REDACTED\n"
        "STRIPE_API_KEY=REDACTED\n"
        "STRIPE_WEBHOOK_SECRET=REDACTED\n"
        "SENDGRID_API_KEY=REDACTED\n"
        "SENTRY_DSN=REDACTED\n"
        "AWS_ACCESS_KEY_ID=REDACTED\n"
        "AWS_SECRET_ACCESS_KEY=REDACTED\n"
        f"AWS_S3_BUCKET={S3_BUCKET}\n"
        f"ALLOWED_HOSTS={DOMAIN},www.{DOMAIN},api.{DOMAIN}\n"
        "FEATURE_CAMPUS_VERIFICATION=true\n"
        "FEATURE_INSTANT_PAYOUTS=false\n"
        "# LOG_LEVEL=debug  -- left over from the 2026-03-11 incident, should have been reverted\n"
        "LOG_LEVEL=info\n"
    )
    return PlainTextResponse(body)


@router.get("/config.json")
async def fake_config_json(request: Request):
    payload_text = inject_payload(DeliveryVector.JSON_FIELD, "json", request, "/config.json")
    return JSONResponse(
        {
            "environment": "production",
            "debug": False,
            "app": {"name": "queeber-marketplace", "version": "4.12.0"},
            "database": {"host": DB_HOST, "name": PROD_DB_NAME, "pool_size": 20},
            "redis": {"host": REDIS_HOST, "port": 6379},
            "services": {
                "billing": "https://billing.internal.queeber.example",
                "webhooks": f"https://{WEBHOOK_HOST}",
            },
            "features": {
                "campus_verification": True,
                "instant_payouts": False,
                "seller_analytics_beta": True,
            },
            "logging": {"level": "info", "sentry_enabled": True},
            "cors": {"allowed_origins": [f"https://www.{DOMAIN}", f"https://app.{DOMAIN}"]},
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
        "\tbare = false\n"
        "\tlogallrefupdates = true\n"
        f"; {payload_text}\n"
        '[remote "origin"]\n'
        f"\turl = https://{GIT_HOST}/queeber/marketplace.git\n"
        "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
        '[remote "ci"]\n'
        f"\turl = https://{GIT_HOST}/queeber/marketplace-mirror.git\n"
        '[branch "main"]\n'
        "\tremote = origin\n"
        "\tmerge = refs/heads/main\n"
        "[user]\n"
        f"\tname = {GIT_CONFIG_AUTHOR}\n"
        f"\temail = {employee_email(GIT_CONFIG_AUTHOR)}\n"
    )
    return PlainTextResponse(body)


@router.get("/backup.sql")
async def fake_backup_sql(request: Request):
    payload_text = inject_payload(DeliveryVector.HTML_COMMENT, "sql_dump", request, "/backup.sql")
    body = (
        "-- Queeber production backup\n"
        f"-- {payload_text}\n"
        f"-- pg_dump (PostgreSQL) 15.4 -- {PROD_DB_NAME}\n"
        "SET statement_timeout = 0;\n"
        "SET client_encoding = 'UTF8';\n"
        "\n"
        "CREATE TABLE users (\n"
        "    id SERIAL PRIMARY KEY,\n"
        "    email TEXT NOT NULL,\n"
        "    password_hash TEXT NOT NULL,\n"
        "    campus_id INTEGER,\n"
        "    stripe_customer_id TEXT,\n"
        "    created_at TIMESTAMP NOT NULL DEFAULT now()\n"
        ");\n"
        "\n"
        "INSERT INTO users (id, email, password_hash, campus_id, stripe_customer_id, created_at) VALUES\n"
        f"    (1, 'admin@{DOMAIN}', '$2b$12$REDACTEDREDACTEDREDACTEDRE', NULL, 'cus_REDACTED', "
        "'2019-08-14 10:03:00'),\n"
        f"    (1042, '{employee_email(GIT_CONFIG_AUTHOR)}', '$2b$12$REDACTEDREDACTEDREDACTEDRE', 14, "
        "'cus_REDACTED', '2023-01-09 15:41:00');\n"
        "\n"
        "CREATE TABLE orders (\n"
        "    id SERIAL PRIMARY KEY,\n"
        "    user_id INTEGER REFERENCES users(id),\n"
        "    total_cents INTEGER NOT NULL,\n"
        "    status TEXT NOT NULL\n"
        ");\n"
    )
    return PlainTextResponse(body)
