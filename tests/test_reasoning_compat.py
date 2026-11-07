"""OpenAI/Foundry tool + reasoning_effort compatibility (port of ChatCompletionToolCompatibility).

Uses the real OpenAI SDK against a mock HTTP transport, so request bodies and the
BadRequestError path are exercised exactly as against Azure Foundry.
"""
import json

import httpx2
import openai

from bongo_ai import agent
from bongo_ai.registry import TOOLS

FOUNDRY_400 = {"error": {"message": "Function tools with reasoning_effort are not supported for marketplace-prompt in "
                                    "/v1/chat/completions. To use function tools, use /v1/responses or set reasoning_effort to 'none'.",
                         "type": "invalid_request_error", "code": "invalid_request_error"}}
UNSUPPORTED_400 = {"error": {"message": "Unsupported parameter: 'reasoning_effort' is not supported with this model.",
                             "type": "invalid_request_error", "code": "unsupported_parameter"}}
OK = {"id": "c1", "object": "chat.completion", "created": 0, "model": "m",
      "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "hello"}}]}


def provider(handler):
    seen = []

    def route(request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content)
        seen.append(body)
        status, payload = handler(body)
        return httpx2.Response(status, json=payload)

    client = openai.OpenAI(api_key="k", base_url="https://res.cognitiveservices.azure.com/openai/v1/",
                           http_client=openai.DefaultHttpxClient(transport=httpx2.MockTransport(route)), max_retries=0)
    return agent.OpenAIProvider(client, "marketplace-prompt"), seen


def test_reasoning_deployment_gets_effort_none_with_tools():
    # Server behaves like the Foundry deployment: tools without effort "none" are rejected.
    p, seen = provider(lambda b: (200, OK) if b.get("reasoning_effort") == "none" else (400, FOUNDRY_400))
    text, calls, _ = p.complete("sys", [p.user_turn("give me a farm report")], [TOOLS["GetLocations"]])
    assert text == "hello" and len(seen) == 1
    assert seen[0]["reasoning_effort"] == "none" and seen[0]["model"] == "marketplace-prompt"


def test_non_reasoning_model_retries_without_the_parameter_and_remembers():
    p, seen = provider(lambda b: (400, UNSUPPORTED_400) if "reasoning_effort" in b else (200, OK))
    history = [p.user_turn("hi")]
    p.complete("sys", history, [TOOLS["GetLocations"]])
    p.complete("sys", history, [TOOLS["GetLocations"]])
    assert [("reasoning_effort" in b) for b in seen] == [True, False, False]


def test_no_tools_sends_no_effort_and_other_errors_still_raise():
    p, seen = provider(lambda b: (200, OK))
    p.complete("sys", [p.user_turn("hi")], [])
    assert "reasoning_effort" not in seen[0]
    p2, _ = provider(lambda b: (400, {"error": {"message": "bad deployment", "type": "x"}}))
    try:
        p2.complete("sys", [p2.user_turn("hi")], [TOOLS["GetLocations"]])
    except openai.BadRequestError:
        pass
    else:
        raise AssertionError("expected BadRequestError")
