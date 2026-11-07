"""Login, tokens and the principal: a Python port of LoginCommandHandler + JwtAuthTokenIssuer.

Security behaviour carried over from the C# server:
  * case-insensitive username, generic "Login failure" message for every reason
  * locked / disabled accounts refused
  * HS256 JWT with the same claim names (sub, UserId, RoleId, Rolename, Permissions,
    tenant_id, company_id, site_id, given_name, family_name, is_temporary, jti, iat)
  * permissions resolved from the role at issue time
  * impersonation requires a-stg-imp and stays inside the actor's company

Demo additions (not in the C# server): PBKDF2 hashing with a per-user salt,
lockout after repeated failures, token revocation (logout) by jti, and a security event log.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import jwt

from . import db
from .config import settings

PBKDF2_ITERATIONS = 210_000


class Perm:
    """Subset of Bongo.Application.Security.Perm used by the demo."""
    VIEW_AI = "p-ai"
    IMPERSONATE = "a-stg-imp"
    MANAGE_USERS = "a-stg-usr"
    VIEW_SECURITY = "p-sec"
    VIEW_OBSERVATIONS = "p-obs"
    ADD_OBSERVATIONS = "a-aobs"
    VIEW_ACTIVITIES = "p-act"
    MANAGE_ACTIVITIES = "a-act-mng"
    AUTHORISE_ACTIVITIES = "a-act-auth"
    VIEW_CHEMICALS = "p-chm"
    VIEW_FUEL = "p-fuel"
    VIEW_REPORT = "p-rpt"
    VIEW_LOCATIONS = "p-loc"


LEADERSHIP_ROLES = {"director", "manager", "farmmanager", "operationsmanager", "supervisor"}


def can_use_chat_write_tools(role_name: str | None) -> bool:
    """FarmLeadership.CanUseChatWriteTools."""
    return bool(role_name) and role_name.strip().lower() in LEADERSHIP_ROLES


# --- passwords ------------------------------------------------------------------------

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return "pbkdf2_sha256${}${}${}".format(
        PBKDF2_ITERATIONS, base64.b64encode(salt).decode(), base64.b64encode(digest).decode())


def verify_password(stored: str, password: str) -> bool:
    try:
        scheme, iterations, salt_b64, digest_b64 = stored.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        expected = base64.b64decode(digest_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(salt_b64), int(iterations))
        return hmac.compare_digest(expected, actual)
    except (ValueError, TypeError):
        return False


# Spend the same time on unknown usernames as on wrong passwords (no user enumeration by timing).
_DUMMY_HASH = hash_password(secrets.token_urlsafe(12))


# --- principal --------------------------------------------------------------------------

@dataclass
class Principal:
    user_id: str = ""
    username: str = ""
    given_name: str = ""
    family_name: str = ""
    role_id: str = ""
    rolename: str = ""
    permissions: list[str] = field(default_factory=list)
    tenant_id: str = ""
    company_id: str = ""
    site_id: str = ""
    jti: str = ""
    expires_at: datetime | None = None
    is_authenticated: bool = False
    impersonated_by: str | None = None

    def has(self, perm: str) -> bool:
        return perm in self.permissions

    @property
    def display_name(self) -> str:
        return f"{self.given_name} {self.family_name}".strip() or self.username

    @staticmethod
    def calendar_runner(tenant_id: str) -> "Principal":
        """The unattended spray planner: no signed-in person, propose-only tools (ChatToolCatalog)."""
        t = db.row("SELECT * FROM tenants WHERE id = ?", (tenant_id,)) or {}
        return Principal(username="calendar-runner", given_name="Calendar", family_name="Runner",
                         tenant_id=tenant_id, company_id=t.get("company_id", ""), site_id=t.get("site_id", ""),
                         is_authenticated=False)

    def claims_for_display(self) -> dict[str, Any]:
        return {
            "sub": self.username, "UserId": self.user_id, "RoleId": self.role_id, "Rolename": self.rolename,
            "Permissions": ",".join(self.permissions), "tenant_id": self.tenant_id, "company_id": self.company_id,
            "site_id": self.site_id, "given_name": self.given_name, "family_name": self.family_name,
            "jti": self.jti, "exp": self.expires_at.isoformat() if self.expires_at else None,
            "impersonated_by": self.impersonated_by,
        }


class AuthError(Exception):
    def __init__(self, message: str = "Not authenticated", status: int = 401):
        super().__init__(message)
        self.status = status


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def log_event(event: str, username: str | None = None, tenant_id: str | None = None,
              detail: str | None = None, ip: str | None = None) -> None:
    with db.write() as conn:
        conn.execute(
            "INSERT INTO security_events (at, tenant_id, username, event, detail, ip) VALUES (?,?,?,?,?,?)",
            (now_utc().isoformat(), tenant_id, username, event, detail, ip))


def permissions_for_role(role_id: str) -> list[str]:
    return [r["permission_code"] for r in db.rows(
        "SELECT permission_code FROM role_permissions WHERE role_id = ? ORDER BY permission_code", (role_id,))]


def issue_token(user: dict[str, Any], impersonated_by: str | None = None) -> dict[str, Any]:
    role = db.row("SELECT * FROM roles WHERE id = ?", (user["role_id"],))
    tenant = db.row("SELECT * FROM tenants WHERE id = ?", (user["tenant_id"],))
    if role is None or tenant is None:
        raise AuthError("User has no role or tenant", 400)
    issued = now_utc()
    expires = issued + settings.token_lifetime
    claims = {
        "iss": settings.jwt_issuer, "aud": settings.jwt_audience,
        "sub": user["username"], "jti": uuid.uuid4().hex, "iat": int(issued.timestamp()),
        "nbf": int(issued.timestamp()), "exp": int(expires.timestamp()),
        "given_name": user["given_name"], "family_name": user.get("family_name") or "",
        "UserId": user["id"], "RoleId": role["id"], "Rolename": role["rolename"],
        "Permissions": ",".join(permissions_for_role(role["id"])),
        "is_temporary": "1" if user.get("is_temporary") else "0",
        "company_id": tenant["company_id"], "site_id": tenant["site_id"], "tenant_id": tenant["id"],
    }
    if impersonated_by:
        claims["act"] = impersonated_by  # RFC 8693 actor claim, so audit can see who is really acting
    token = jwt.encode(claims, settings.jwt_key, algorithm="HS256")
    return {"token": token, "expires": expires.isoformat(), "message": "OK", "isSuccess": True}


def login(username: str | None, password: str | None, ip: str | None = None) -> dict[str, Any]:
    failure = {"isSuccess": False, "message": "Login failure", "token": None}
    if not username or not username.strip():
        return failure
    name = username.strip()
    user = db.row("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (name,))
    if user is None:
        verify_password(_DUMMY_HASH, password or "")
        log_event("login_failed", name, None, "unknown username", ip)
        return failure

    if user["lockout_until"] and datetime.fromisoformat(user["lockout_until"]) > now_utc():
        verify_password(_DUMMY_HASH, password or "")  # a fast reply would show the username exists
        log_event("login_failed", user["username"], user["tenant_id"], "temporary lockout active", ip)
        return failure

    if not verify_password(user["pwd"], password or ""):
        failures = user["failed_logins"] + 1
        lockout = None
        if failures >= settings.login_max_failures:
            lockout = (now_utc() + settings.login_lockout).isoformat()
            failures = 0
        with db.write() as conn:
            conn.execute("UPDATE users SET failed_logins = ?, lockout_until = ? WHERE id = ?",
                         (failures, lockout, user["id"]))
        log_event("login_failed", user["username"], user["tenant_id"],
                  "password mismatch" + (" - locked for 15 minutes" if lockout else ""), ip)
        return failure

    if user["is_locked"]:
        log_event("login_failed", user["username"], user["tenant_id"], "account locked", ip)
        return failure
    if user["is_disabled"]:
        log_event("login_failed", user["username"], user["tenant_id"], "account disabled", ip)
        return failure

    with db.write() as conn:
        conn.execute("UPDATE users SET failed_logins = 0, lockout_until = NULL WHERE id = ?", (user["id"],))
    log_event("login_ok", user["username"], user["tenant_id"], None, ip)
    return issue_token(user)


def decode_token(token: str) -> Principal:
    try:
        claims = jwt.decode(token, settings.jwt_key, algorithms=["HS256"],
                            audience=settings.jwt_audience, issuer=settings.jwt_issuer,
                            options={"require": ["exp", "iat", "sub", "jti"]})
    except jwt.ExpiredSignatureError as exc:
        raise AuthError("Token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise AuthError("Invalid token") from exc

    if db.scalar("SELECT 1 FROM revoked_tokens WHERE jti = ?", (claims["jti"],)):
        raise AuthError("Token revoked")

    # Re-check the account on every request: disabling a user cuts off live tokens too.
    user = db.row("SELECT is_locked, is_disabled FROM users WHERE id = ?", (claims.get("UserId"),))
    if user is None or user["is_locked"] or user["is_disabled"]:
        raise AuthError("Account is no longer active")
    # An impersonation token also dies with the real person behind it.
    if claims.get("act"):
        actor = db.row("SELECT is_locked, is_disabled FROM users WHERE username = ? COLLATE NOCASE", (claims["act"],))
        if actor is None or actor["is_locked"] or actor["is_disabled"]:
            raise AuthError("Account is no longer active")

    return Principal(
        user_id=claims.get("UserId", ""), username=claims["sub"], given_name=claims.get("given_name", ""),
        family_name=claims.get("family_name", ""), role_id=claims.get("RoleId", ""),
        rolename=claims.get("Rolename", ""),
        permissions=[p for p in claims.get("Permissions", "").split(",") if p],
        tenant_id=claims.get("tenant_id", ""), company_id=claims.get("company_id", ""),
        site_id=claims.get("site_id", ""), jti=claims["jti"],
        expires_at=datetime.fromtimestamp(claims["exp"], timezone.utc),
        is_authenticated=True, impersonated_by=claims.get("act"),
    )


def revoke(principal: Principal) -> None:
    with db.write() as conn:
        conn.execute("INSERT OR IGNORE INTO revoked_tokens (jti, expires_at, revoked_at) VALUES (?,?,?)",
                     (principal.jti, (principal.expires_at or now_utc()).isoformat(), now_utc().isoformat()))
        conn.execute("DELETE FROM revoked_tokens WHERE expires_at < ?", (now_utc().isoformat(),))
    log_event("logout", principal.username, principal.tenant_id, f"revoked jti {principal.jti[:8]}…")


def impersonate(actor: Principal, target_user_id: str) -> dict[str, Any]:
    """AuthController.Impersonate."""
    if not actor.has(Perm.IMPERSONATE):
        raise AuthError("Forbidden", 403)
    if actor.impersonated_by:  # no chains: the act claim must always name the real person
        raise AuthError("Forbidden: already impersonating", 403)
    target = db.row("SELECT * FROM users WHERE id = ?", (target_user_id,))
    if target is None:
        raise AuthError("Not found", 404)
    if target["is_disabled"] or target["is_locked"]:
        raise AuthError("Target user is disabled or locked.", 400)
    target_tenant = db.row("SELECT * FROM tenants WHERE id = ?", (target["tenant_id"],))
    if target_tenant is None or target_tenant["company_id"] != actor.company_id:
        log_event("impersonation_denied", actor.username, actor.tenant_id, f"target {target['username']} outside company")
        raise AuthError("Forbidden", 403)
    extra = sorted(set(permissions_for_role(target["role_id"])) - set(actor.permissions))
    if extra:  # impersonation must not be a way to gain permissions
        log_event("impersonation_denied", actor.username, actor.tenant_id,
                  f"target {target['username']} holds permissions the actor lacks: {', '.join(extra)}")
        raise AuthError("Forbidden", 403)
    log_event("impersonation", actor.username, actor.tenant_id, f"now acting as {target['username']}")
    result = issue_token(target, impersonated_by=actor.username)
    result.update(userId=target["id"], username=target["username"],
                  displayName=f"{target['given_name']} {target.get('family_name') or ''}".strip())
    return result
