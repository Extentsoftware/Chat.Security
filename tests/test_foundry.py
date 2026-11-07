"""Azure AI Foundry configuration: endpoint resolution and client wiring (no network)."""
import pytest

from bongo_ai import agent
from bongo_ai.config import settings


@pytest.fixture
def foundry(monkeypatch):
    def configure(endpoint, api=""):
        monkeypatch.setattr(settings, "llm_provider", "")
        monkeypatch.setattr(settings, "foundry_endpoint", endpoint)
        monkeypatch.setattr(settings, "foundry_deployment", "my-deployment")
        monkeypatch.setattr(settings, "foundry_api_key", "test-key")
        monkeypatch.setattr(settings, "foundry_api", api)
    return configure


@pytest.mark.parametrize("endpoint, expected", [
    ("https://res.cognitiveservices.azure.com", "https://res.cognitiveservices.azure.com/openai/v1/"),
    ("https://res.cognitiveservices.azure.com/", "https://res.cognitiveservices.azure.com/openai/v1/"),
    ("https://res.openai.azure.com/openai/v1", "https://res.openai.azure.com/openai/v1/"),
    ("https://res.services.ai.azure.com/api/projects/farm", "https://res.services.ai.azure.com/api/projects/farm/"),
])
def test_openai_endpoint_resolution_matches_csharp_factory(foundry, endpoint, expected):
    foundry(endpoint)
    assert settings.provider() == "foundry"
    assert settings.foundry_kind() == "openai"
    assert settings.foundry_base_url() == expected


def test_foundry_takes_priority_and_needs_all_three(foundry, monkeypatch):
    foundry("https://res.cognitiveservices.azure.com")
    monkeypatch.setenv("OPENAI_API_KEY", "x")
    assert settings.provider() == "foundry"
    monkeypatch.setattr(settings, "foundry_deployment", "")
    assert settings.provider() == "openai"


def test_gpt_deployment_uses_openai_client_with_deployment_as_model(foundry):
    foundry("https://res.cognitiveservices.azure.com")
    p = agent.make_provider()
    assert isinstance(p, agent.OpenAIProvider)
    assert str(p.client.base_url) == "https://res.cognitiveservices.azure.com/openai/v1/"
    assert p.model == "my-deployment"


def test_claude_deployment_uses_anthropic_foundry_without_server_fallbacks(foundry):
    foundry("https://res.services.ai.azure.com/anthropic/v1/messages")
    p = agent.make_provider()
    assert isinstance(p, agent.AnthropicProvider)
    assert type(p.client).__name__ == "AnthropicFoundry"
    assert str(p.client.base_url).rstrip("/") == "https://res.services.ai.azure.com/anthropic"
    assert p.model == "my-deployment" and p.server_fallbacks is False


def test_bad_endpoint_is_rejected(foundry):
    foundry("res.cognitiveservices.azure.com")
    with pytest.raises(ValueError):
        settings.foundry_base_url()
