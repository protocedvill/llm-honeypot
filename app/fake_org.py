"""Single source of truth for facts about the fake company ("Queeber")
that must stay consistent across decoy routes and templates -- the
leadership team named in about.html, the internal hostnames referenced in
leaked config files, the DB name a leaked backup and a leaked .env must
agree on, etc. Centralizing these here is what keeps decoy_config.py's
leak files, decoy_api.py's stub data, and decoy_actuator.py's fake
microservice from drifting out of sync with each other."""

from dataclasses import dataclass

COMPANY_NAME = "Queeber"
DOMAIN = "queeber.example"
FOUNDED_YEAR = 2019


@dataclass(frozen=True)
class Office:
    city: str
    description: str


OFFICES = (
    Office("Austin, TX", "Headquarters — Product, Engineering, Trust & Safety"),
    Office("Denver, CO", "Engineering & Infrastructure"),
    Office("Lisbon, Portugal", "Engineering, EU Customer Success"),
)


@dataclass(frozen=True)
class Executive:
    name: str
    role: str


LEADERSHIP = (
    Executive("Dana Whitfield", "Co-Founder & CEO"),
    Executive("Marcus Okoye", "Co-Founder & CTO"),
    Executive("Priya Ramaswamy", "VP of Engineering"),
    Executive("Tomas Novak", "VP of Trust & Safety"),
)

# Wider staff pool (includes leadership) for identities that need to look
# like an ordinary employee rather than an executive -- git commit
# authorship on a leaked .git/config, an admin/service-account row in a
# leaked backup, etc.
EMPLOYEES = (
    "Dana Whitfield",
    "Marcus Okoye",
    "Priya Ramaswamy",
    "Tomas Novak",
    "Renee Castillo",
    "Kwame Osei",
    "Ines Bergstrom",
    "Alex Dunmore",
    "Sana Farooqi",
    "Ben Halloran",
)

# The employee whose identity appears on the leaked .git/config -- fixed
# rather than randomized, since a real leaked file doesn't change on every
# fetch. An infra engineer is the plausible one to have `git config
# user.*` set locally on a deploy box.
GIT_CONFIG_AUTHOR = "Renee Castillo"

# Internal hostnames referenced across decoy leak files (.env, .git/config,
# backup.sql, /actuator/env) -- kept consistent everywhere so an attacker
# cross-referencing multiple leaks sees one coherent internal network
# instead of four unrelated guesses.
DB_HOST = "db.internal"
REDIS_HOST = "redis.internal"
GIT_HOST = f"git.internal.{DOMAIN}"
WEBHOOK_HOST = f"hooks.{DOMAIN}"
S3_BUCKET = "queeber-prod-uploads"

PROD_DB_NAME = "queeber_prod"


def employee_email(name: str) -> str:
    first, _, last = name.partition(" ")
    return f"{first.lower()}.{last.lower()}@{DOMAIN}"
