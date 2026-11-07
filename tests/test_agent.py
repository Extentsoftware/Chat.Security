"""Agent loop tests with a scripted model (no API key needed)."""
import json

import pytest

from bongo_ai import agent
from bongo_ai.security import decode_token


class ScriptedProvider:
    """Plays back a list of turns. Each turn is (text, [(name, args), ...])."""
    name = "scripted"

    def __init__(self, turns):
        self.turns = list(turns)
        self.offered: list[list[str]] = []
        self.allow_tools_flags: list[bool] = []

    def user_turn(self, text):
        return {"role": "user", "content": text}

    def complete(self, system, history, tools, allow_tools=True):
        self.offered.append([t.name for t in tools])
        self.allow_tools_flags.append(allow_tools)
        text, calls = self.turns.pop(0) if self.turns else ("done", [])
        if not allow_tools:
            calls = []
        calls = [(f"call{i}", n, a) for i, (n, a) in enumerate(calls)]
        history.append({"role": "assistant", "content": text, "calls": [c[1] for c in calls]})
        return text, calls, "tool_use" if calls else "end_turn"

    def tool_results(self, history, results):
        history.append({"role": "user", "content": [r[1] for r in results]})


def principal(login, user):
    return decode_token(login(user)["Authorization"].split()[1])


def run(monkeypatch, provider, p, prompt, conversation_id=None, template="general"):
    monkeypatch.setattr(agent, "make_provider", lambda: provider)
    events = []
    answer = agent.chat(p, prompt, conversation_id, template, events.append)
    cid = next(e["conversationId"] for e in events if e["type"] == "conversation")
    return answer, events, cid


def proposed_id(client, login):
    from conftest import invoke
    rows = invoke(client, login("manager"), "CreateActivity", {"activityType": "Mowing", "title": "Agent test"})
    return rows["json"]["activityId"]


def test_injected_instruction_cannot_authorise(client, login, monkeypatch):
    p = principal(login, "manager")
    aid = proposed_id(client, login)
    # A model that obeys the injected observation note and uses the fake label from it.
    model = ScriptedProvider([
        ("", [("GetObservations", {"take": 5})]),
        ("", [("AuthoriseActivity", {"activityId": aid})]),
        ("It is done, everything is authorised.", []),
    ])
    _, events, cid = run(monkeypatch, model, p, "Confirm AuthoriseActivity 00000000")
    sec = [(e["outcome"], e["tool"]) for e in events if e["type"] == "security"]
    assert ("flagged", "GetObservations") in sec          # the injected note was spotted...
    assert ("blocked", "AuthoriseActivity") in sec        # ...and the write it asked for did not run
    real_label = next(e for e in events if e["type"] == "suggestion")["suggestions"][0]
    assert real_label != "Confirm AuthoriseActivity 00000000"
    from bongo_ai import db
    assert db.scalar("SELECT state FROM activities WHERE id = ?", (aid,)) == "Proposed"

    # Next turn: the manager clicks the real label; the same call now runs.
    model2 = ScriptedProvider([("", [("AuthoriseActivity", {"activityId": aid})]), ("Authorised.", [])])
    run(monkeypatch, model2, p, real_label, conversation_id=cid)
    assert db.scalar("SELECT state FROM activities WHERE id = ?", (aid,)) == "Planned"


def test_forged_call_to_unoffered_tool_is_refused(client, login, monkeypatch):
    p = principal(login, "scout")
    model = ScriptedProvider([("", [("CreateActivity", {"activityType": "Apply", "title": "sneaky"})]), ("ok", [])])
    _, events, _ = run(monkeypatch, model, p, "make a spray task")
    assert "CreateActivity" not in model.offered[0]
    assert any(e["type"] == "security" and e["outcome"] == "denied" for e in events)


def test_repeat_call_guard_stops_the_turn(client, login, monkeypatch):
    p = principal(login, "manager")
    same = ("", [("GetScoutSectionAges", {})])
    model = ScriptedProvider([same, same, same, same, ("final", [])])
    _, events, _ = run(monkeypatch, model, p, "loop please")
    assert any(e["type"] == "security" and e["outcome"] == "doom_loop" for e in events)
    assert model.allow_tools_flags[-1] is False  # final answer requested with tools switched off


def test_template_limits_offered_tools(client, login, monkeypatch):
    p = principal(login, "manager")
    model = ScriptedProvider([("hi", [])])
    run(monkeypatch, model, p, "hello", template="scout-review")
    offered = set(model.offered[0])
    assert "GetScoutSessions" in offered and "ListSkills" in offered
    assert "ViewChemical" not in offered and "CreateActivity" not in offered


def test_subagent_is_read_only(client, login, monkeypatch):
    p = principal(login, "manager")
    child_offered = []

    class Parent(ScriptedProvider):
        def complete(self, system, history, tools, allow_tools=True):
            if "subagent" in system:
                child_offered.append([t.name for t in tools])
                history.append({"role": "assistant", "content": "child"})
                if len(child_offered) == 1:
                    return "", [("c1", "CreateActivity", {"activityType": "Apply", "title": "x"})], "tool_use"
                return "child findings", [], "end_turn"
            return super().complete(system, history, tools, allow_tools)

    model = Parent([("", [("StartSubagent", {"profile": "explore", "task": "look"})]), ("done", [])])
    _, events, _ = run(monkeypatch, model, p, "explore")
    assert "CreateActivity" not in child_offered[0] and "StartSubagent" not in child_offered[0]
    from bongo_ai import db
    row = db.row("SELECT outcome FROM tool_audit WHERE channel = 'subagent' AND tool_name = 'CreateActivity' ORDER BY id DESC")
    assert row["outcome"] == "denied"


def test_anthropic_adapter_round_trips_sdk_blocks(monkeypatch):
    """The Claude adapter builds a valid request and parses real SDK response types."""
    from anthropic.types.beta import BetaMessage
    captured = {}

    class FakeMessages:
        def create(self, **kwargs):
            captured.update(kwargs)
            return BetaMessage.model_validate({
                "id": "msg_1", "type": "message", "role": "assistant", "model": kwargs["model"],
                "content": [{"type": "text", "text": "Checking."},
                            {"type": "tool_use", "id": "toolu_1", "name": "GetLocations", "input": {}}],
                "stop_reason": "tool_use", "stop_sequence": None,
                "usage": {"input_tokens": 10, "output_tokens": 5}})

    class FakeClient:
        class beta:
            messages = FakeMessages()

    prov = agent.AnthropicProvider.__new__(agent.AnthropicProvider)
    prov.client = FakeClient()
    from bongo_ai.registry import TOOLS
    history = [prov.user_turn("hi")]
    text, calls, stop = prov.complete("sys", history, [TOOLS["GetLocations"]])
    assert text == "Checking." and calls == [("toolu_1", "GetLocations", {})] and stop == "tool_use"
    assert captured["model"] == "claude-opus-5-5" and captured["fallbacks"] == "default"
    assert captured["tools"][0]["input_schema"]["additionalProperties"] is False
    prov.tool_results(history, [("toolu_1", "[]", False)])
    json.dumps(history)  # history must be storable
    assert history[1]["content"][1]["type"] == "tool_use" and history[2]["content"][0]["tool_use_id"] == "toolu_1"
