"""Spring Boot Actuator-lookalike routes -- reads as a separate Java
microservice in Acme's fleet. Detection only, no inject_payload calls.

/actuator/env's sanitization of password/secret/key/token/credential-shaped
property values is Spring Boot's own actual default behavior since 1.5, not
a bespoke rule invented for this decoy -- a real modern Spring Boot app
behaves exactly this way out of the box."""

import re

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter()

_JNDI_PATTERN = re.compile(r"\$\{jndi:", re.IGNORECASE)
_SENSITIVE_KEY_PATTERN = re.compile(
    r"password|secret|key|token|credential", re.IGNORECASE
)


def _sanitize(key: str, value: str) -> str:
    return "******" if _SENSITIVE_KEY_PATTERN.search(key) else value


@router.get("/actuator/health")
async def actuator_health():
    return JSONResponse({"status": "UP"})


@router.get("/actuator/env")
async def actuator_env(request: Request):
    if any(_JNDI_PATTERN.search(value) for value in request.headers.values()):
        request.state.vuln_probe_detected = True

    raw_properties = {
        "PATH": "/usr/bin:/bin:/usr/local/bin",
        "JAVA_HOME": "/usr/lib/jvm/java-17-openjdk",
        "DATABASE_PASSWORD": "REDACTED",
        "spring.application.name": "acme-invoicing-service",
        "spring.profiles.active": "production",
        "spring.datasource.url": "jdbc:postgresql://db.internal:5432/invoicing",
        "spring.datasource.username": "invoicing_svc",
        "spring.datasource.password": "REDACTED",
        "management.endpoint.health.show-details": "when-authorized",
        "acme.billing.api-key": "REDACTED",
        "acme.billing.webhook-secret": "REDACTED",
    }
    return JSONResponse(
        {
            "activeProfiles": ["production"],
            "propertySources": [
                {
                    "name": "systemEnvironment",
                    "properties": {
                        "PATH": {"value": raw_properties["PATH"]},
                        "JAVA_HOME": {"value": raw_properties["JAVA_HOME"]},
                        "DATABASE_PASSWORD": {
                            "value": _sanitize("DATABASE_PASSWORD", raw_properties["DATABASE_PASSWORD"])
                        },
                    },
                },
                {
                    "name": "applicationConfig: [classpath:/application.yml]",
                    "properties": {
                        k: {"value": _sanitize(k, v)}
                        for k, v in raw_properties.items()
                        if k not in ("PATH", "JAVA_HOME", "DATABASE_PASSWORD")
                    },
                },
            ],
        }
    )


@router.get("/actuator/heapdump")
async def actuator_heapdump():
    # Modern Spring Boot doesn't expose heapdump by default -- matching
    # that, not a special case bolted on for this decoy.
    return JSONResponse(
        {"error": "Endpoint 'heapdump' is disabled"},
        status_code=404,
    )
