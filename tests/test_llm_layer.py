"""The live-mode code path, exercised without network by faking the OpenAI-compatible client."""
import json
from types import SimpleNamespace

import pytest

from talos import Checker, Gate, Ledger, Limits, Workspace, close_day
from talos.demo import SCOPE, TASK, build_workspace
from talos.llm import NEBIUS_BASE_URL, NebiusLLM, extract_json
from talos.maker import Maker


def test_extract_json_handles_think_blocks_and_prose():
    t = '<think>I should {maybe} read the file</think>Sure! Here you go:\n{"tool": "read_file", "args": {"path": "a.py"}} done.'
    assert extract_json(t) == {"tool": "read_file", "args": {"path": "a.py"}}
    assert extract_json("no json here") is None
    assert extract_json('{"a": "brace } inside string"}') == {"a": "brace } inside string"}
    assert extract_json('garbage {not json} then {"ok": true}') == {"ok": True}


def test_nebius_client_uses_token_factory_endpoint_and_meters_usage(monkeypatch):
    monkeypatch.setenv("NEBIUS_API_KEY", "test-key")
    llm = NebiusLLM("nvidia/some-model")
    assert str(llm.client.base_url) == NEBIUS_BASE_URL
    fake = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="hi"))],
                           usage=SimpleNamespace(prompt_tokens=10, completion_tokens=3))
    llm.client.chat.completions.create = lambda **kw: fake
    assert llm.chat([{"role": "user", "content": "x"}]) == "hi"
    assert llm.usage == {"model": "nvidia/some-model", "calls": 1, "prompt_tokens": 10, "completion_tokens": 3}


def test_missing_key_is_a_clear_error(monkeypatch):
    monkeypatch.delenv("NEBIUS_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="NEBIUS_API_KEY"):
        NebiusLLM("m")


class Messy:
    """A 'real model' that wraps JSON in prose and <think> blocks and sometimes rambles."""

    name = "messy-maker"

    def __init__(self, replies):
        self.replies = list(replies)

    def chat(self, messages, **kw):
        return self.replies.pop(0) if self.replies else '{"done": true, "summary": "ok"}'


def _gate(tmp_path, checker_llm=None):
    build_workspace(tmp_path / "ws")
    ws = Workspace(tmp_path / "ws", outbox=tmp_path / "outbox.jsonl")
    chk = Checker(checker_llm) if checker_llm else None
    from talos import HeuristicChecker
    return Gate(ws, Ledger(tmp_path / "l.jsonl"), chk or HeuristicChecker(), Limits())


def test_maker_loop_survives_messy_model_output(tmp_path):
    gate = _gate(tmp_path)
    s = gate.open_session(TASK, SCOPE, maker_model="messy-maker")
    replies = [
        '<think>plan it</think>{"plan": [{"tool": "read_file", "target": "src/calc.py"}]}',
        "Let me look at the code.\n```json\n" + json.dumps({"tool": "read_file", "args": {"path": "src/calc.py"}}) + "\n```",
        "hmm I am not sure what to do",              # unparsable: gets one retry nudge
        json.dumps({"tool": "read_file", "args": {"path": "src/calc.py"}}),
        json.dumps({"done": True, "summary": "looked around"}),
    ]
    res = Maker(Messy(replies)).run(gate, s)
    assert res.summary == "looked around" and res.steps == 2


def test_maker_stops_after_repeated_garbage(tmp_path):
    gate = _gate(tmp_path)
    s = gate.open_session(TASK, SCOPE, maker_model="messy-maker")
    res = Maker(Messy(['{"plan": []}', "blah", "blah blah"])).run(gate, s)
    assert res.stopped == "unparsable replies"


def test_maker_api_failure_does_not_crash_the_day(tmp_path):
    class Down:
        name = "down"

        def chat(self, *a, **k):
            raise ConnectionError("Token Factory unreachable")

    gate = _gate(tmp_path)
    s = gate.open_session(TASK, SCOPE, maker_model="down")
    res = Maker(Down()).run(gate, s)
    assert "model error" in res.stopped
    assert close_day(gate, s).chain_ok


def test_unknown_tool_from_model_is_blocked_and_logged(tmp_path):
    gate = _gate(tmp_path)
    s = gate.open_session(TASK, SCOPE, maker_model="messy-maker")
    replies = ['{"plan": []}', json.dumps({"tool": "format_disk", "args": {}}), '{"done": true, "summary": "x"}']
    Maker(Messy(replies)).run(gate, s)
    acts = [e for e in gate.ledger.entries() if e["kind"] == "action"]
    assert acts[0]["decision"] == "blocked" and "unknown_tool" in acts[0]["tags"]
