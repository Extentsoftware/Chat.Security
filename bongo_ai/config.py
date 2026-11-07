"""Runtime settings, read from environment variables (see README)."""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from datetime import timedelta, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Farm calendar days are Africa/Harare (UTC+2, no daylight saving) as in ScoutCalendarDate.
FARM_TZ = timezone(timedelta(hours=2), "Africa/Harare")


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


@dataclass
class Settings:
    db_path: Path = field(default_factory=lambda: Path(_env("BONGO_DB", str(BASE_DIR / "data" / "bongo_demo.db"))))
    # HS256 signing key. Generated per process when unset, so tokens do not survive a restart.
    jwt_key: str = field(default_factory=lambda: _env("BONGO_JWT_KEY") or secrets.token_urlsafe(48))
    jwt_issuer: str = field(default_factory=lambda: _env("BONGO_JWT_ISSUER", "bongo-ai-demo"))
    jwt_audience: str = field(default_factory=lambda: _env("BONGO_JWT_AUDIENCE", "bongo-ai-demo"))
    # The C# issuer uses 10 days. A demo keeps it short so expiry is visible.
    token_lifetime: timedelta = field(default_factory=lambda: timedelta(minutes=int(_env("BONGO_TOKEN_MINUTES", "120"))))
    login_max_failures: int = 5
    login_lockout: timedelta = timedelta(minutes=15)

    llm_provider: str = field(default_factory=lambda: _env("BONGO_LLM_PROVIDER").lower())
    anthropic_model: str = field(default_factory=lambda: _env("BONGO_ANTHROPIC_MODEL", "claude-opus-5-5"))
    anthropic_effort: str = field(default_factory=lambda: _env("BONGO_ANTHROPIC_EFFORT", "medium"))
    openai_model: str = field(default_factory=lambda: _env("BONGO_OPENAI_MODEL", "gpt-5"))
    # Azure AI Foundry: the deployment name is the model. A GPT deployment is called through the
    # OpenAI v1 API (as Bongo.AI's OpenAIClientFactory does); a Claude deployment through the
    # Anthropic Messages API at <resource>/anthropic.
    foundry_endpoint: str = field(default_factory=lambda: _env("BONGO_FOUNDRY_ENDPOINT"))
    foundry_deployment: str = field(default_factory=lambda: _env("BONGO_FOUNDRY_DEPLOYMENT"))
    foundry_api_key: str = field(default_factory=lambda: _env("BONGO_FOUNDRY_API_KEY"))
    foundry_api: str = field(default_factory=lambda: _env("BONGO_FOUNDRY_API").lower())  # openai | anthropic | "" (auto)
    # Allow-list of remote MCP servers and their approved tool pins (see mcp_servers.example.json).
    mcp_servers_file: Path = field(default_factory=lambda: Path(_env("BONGO_MCP_SERVERS", str(BASE_DIR / "mcp_servers.json"))))
    max_tool_calls: int = 24  # ToolInvocationFilter.InteractiveToolCallCap
    weather_online: bool = field(default_factory=lambda: _env("BONGO_WEATHER_ONLINE", "1") != "0")

    def provider(self) -> str:
        """foundry | anthropic | openai | offline. Explicit setting wins; otherwise whichever is configured."""
        if self.llm_provider in ("foundry", "anthropic", "openai", "offline"):
            return self.llm_provider
        if self.foundry_endpoint and self.foundry_api_key and self.foundry_deployment:
            return "foundry"
        if os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"):
            return "anthropic"
        if os.environ.get("OPENAI_API_KEY"):
            return "openai"
        return "offline"


    def foundry_kind(self) -> str:
        """Which API the Foundry deployment speaks: explicit setting, else '/anthropic' in the URL, else openai."""
        if self.foundry_api in ("openai", "anthropic"):
            return self.foundry_api
        return "anthropic" if "/anthropic" in self.foundry_endpoint.lower() else "openai"

    def foundry_base_url(self) -> str:
        """Port of OpenAIClientFactory.ResolveEndpoint (+ the Anthropic path for Claude deployments).

        https://res.cognitiveservices.azure.com       -> https://res.cognitiveservices.azure.com/openai/v1/
        https://res.openai.azure.com/openai/v1         -> unchanged (trailing slash added)
        https://res.services.ai.azure.com/anthropic/v1 -> https://res.services.ai.azure.com/anthropic
        """
        from urllib.parse import urlparse
        url = self.foundry_endpoint.strip()
        parsed = urlparse(url)
        if parsed.scheme not in ("https", "http") or not parsed.netloc:
            raise ValueError(f"Invalid BONGO_FOUNDRY_ENDPOINT '{url}'. Use e.g. https://my-resource.cognitiveservices.azure.com")
        origin = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path.rstrip("/")
        if self.foundry_kind() == "anthropic":
            return origin + "/anthropic"     # the SDK appends /v1/messages
        if "/openai" in path.lower() or "/api/projects/" in path.lower():
            return url.rstrip("/") + "/"
        return origin + "/openai/v1/"

    def model_label(self) -> str | None:
        return {"foundry": f"{self.foundry_deployment} (Azure Foundry, {self.foundry_kind()} API)",
                "anthropic": self.anthropic_model, "openai": self.openai_model}.get(self.provider())


settings = Settings()
