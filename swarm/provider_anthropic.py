"""Anthropic (Claude) provider — FRONTIER BENCHMARK ONLY, never the submission.

The submission must run on Nebius Token Factory + NVIDIA Nemotron or it's an
automatic DQ (see CLAUDE.md). This module exists so the SAME three-tier harness
can also run on Claude (Opus 5.5 / Sonnet 5.5 / Haiku 5.5) as a control, giving an
open-models (Nemotron) vs frontier-models (Claude) comparison from one codebase —
`duel_record.provider` + `analyze.py` ablation_provider do the rest.

Uses the official `anthropic` SDK (not an OpenAI-compatible shim) and adapts
between the OpenAI chat-completions shape the agents speak and the Anthropic
Messages API. Sampling params (temperature/top_p) and forced tool_choice are
dropped on purpose — Claude Opus 5.5 rejects them with a 400.
"""
import json
import sys as _sys
import time
from pathlib import Path

import yaml

_sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # runnable as a script
from swarm.llm import UsageCounter, LLMError, _CONFIG

# Tier -> Claude model. Ultra=deep reasoning, Super=fast tool-calling, Nano=triage.
CLAUDE_TIERS = {"ultra": "claude-opus-5-5", "super": "claude-sonnet-5-5", "nano": "claude-haiku-5-5"}


# --- OpenAI-shaped shim objects the agents already consume ---------------------
class _Fn:
    def __init__(self, name, arguments):
        self.name = name
        self.arguments = arguments


class _ToolCall:
    def __init__(self, id, name, arguments):
        self.id = id
        self.type = "function"
        self.function = _Fn(name, arguments)


class _AsstMsg:
    role = "assistant"

    def __init__(self, content, tool_calls):
        self.content = content
        self.tool_calls = tool_calls


_STOP_MAP = {"tool_use": "tool_calls", "end_turn": "stop", "max_tokens": "length",
             "stop_sequence": "stop", "pause_turn": "tool_calls"}


class _Choice:
    def __init__(self, message, finish_reason="stop"):
        self.message = message
        self.finish_reason = finish_reason


class _Usage:
    def __init__(self, prompt_tokens, completion_tokens):
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens


class _Resp:
    def __init__(self, choices, usage):
        self.choices = choices
        self.usage = usage


def _get(m, key, default=None):
    return m.get(key, default) if isinstance(m, dict) else getattr(m, key, default)


def to_anthropic_messages(messages):
    """OpenAI chat history -> (system_str, anthropic_messages). Groups consecutive
    tool results into one user turn (Anthropic requires tool_result in a user turn)."""
    system_parts, out, pending = [], [], []

    def flush():
        if pending:
            out.append({"role": "user", "content": list(pending)})
            pending.clear()

    for m in messages:
        role = _get(m, "role")
        if role == "system":
            system_parts.append(str(_get(m, "content", "")))
        elif role == "tool":
            pending.append({"type": "tool_result",
                            "tool_use_id": _get(m, "tool_call_id"),
                            "content": str(_get(m, "content", ""))})
        elif role == "user":
            flush()
            out.append({"role": "user", "content": _get(m, "content", "")})
        elif role == "assistant":
            flush()
            blocks = []
            content = _get(m, "content")
            if content:
                blocks.append({"type": "text", "text": content})
            for tc in (_get(m, "tool_calls") or []):
                fn = _get(tc, "function")
                name = _get(fn, "name") if fn is not None else _get(tc, "name")
                args = _get(fn, "arguments") if fn is not None else _get(tc, "arguments")
                try:
                    inp = json.loads(args) if args else {}
                except (ValueError, TypeError):
                    inp = {}
                blocks.append({"type": "tool_use", "id": _get(tc, "id"), "name": name, "input": inp})
            out.append({"role": "assistant", "content": blocks or [{"type": "text", "text": ""}]})
    flush()
    return ("\n\n".join(p for p in system_parts if p) or None), out


def to_anthropic_tools(tools):
    out = []
    for t in tools or []:
        f = t.get("function", t)
        out.append({"name": f["name"], "description": f.get("description", ""),
                    "input_schema": f.get("parameters") or {"type": "object", "properties": {}}})
    return out


class AnthropicRouter:
    """Drop-in for swarm.llm.Router, backed by Claude. Benchmark use only."""

    def __init__(self, config_path=_CONFIG, on_call=None, timeout=None, max_retries=None,
                 force_model=None):
        import anthropic  # imported here so the module loads without the package (tests)
        self.cfg = yaml.safe_load(Path(config_path).read_text())
        self.models = (self.cfg.get("anthropic") or {}).get("tiers") or dict(CLAUDE_TIERS)
        self.force_model = force_model   # pin every role to one checkpoint (monitor matrix)
        self.client = anthropic.Anthropic(
            timeout=float(timeout if timeout is not None else 60),
            max_retries=int(max_retries if max_retries is not None else 4),
        )
        self.usage = UsageCounter()
        self._on_call = on_call

    def model_for(self, role):
        tier = self.cfg["roles"].get(role, role)
        if self.force_model:
            return tier, self.force_model
        return tier, self.models.get(tier, CLAUDE_TIERS.get(tier, "claude-opus-5-5"))

    def _emit(self, tier, model, latency, usage):
        self.usage.record(tier, model, latency, usage)
        if self._on_call:
            try:
                self._on_call({"tier": tier, "model": model, "latency_s": round(latency, 2),
                               "prompt_tokens": usage.prompt_tokens, "completion_tokens": usage.completion_tokens})
            except Exception:
                pass

    def _create(self, tier, model, messages, tools=None, max_tokens=1024):
        system, amsgs = to_anthropic_messages(messages)
        kw = {"model": model, "max_tokens": max_tokens, "messages": amsgs}
        if system:
            kw["system"] = system
        if tools:
            kw["tools"] = to_anthropic_tools(tools)
        # Sampling params and forced tool_choice are intentionally omitted (Opus 5.5 -> 400).
        t0 = time.monotonic()
        try:
            r = self.client.messages.create(**kw)
        except Exception as e:
            raise LLMError(f"{tier}/{model} (anthropic) call failed after retries: {e}") from e
        # A safety refusal (stop_reason=refusal) returns empty content, not an exception.
        # Surface it as LLMError so callers degrade gracefully (e.g. red falls back to
        # scripted). Claude's cyber classifier declines the offensive red role — a real
        # open-vs-frontier finding, not something to work around.
        if getattr(r, "stop_reason", None) == "refusal":
            cat = getattr(getattr(r, "stop_details", None), "category", None)
            raise LLMError(f"{tier}/{model} refused (safety classifier, category={cat})")
        usage = _Usage(getattr(r.usage, "input_tokens", 0), getattr(r.usage, "output_tokens", 0))
        self._emit(tier, model, time.monotonic() - t0, usage)
        return r

    def chat(self, role, messages, **kw):
        tier, model = self.model_for(role)
        r = self._create(tier, model, messages, max_tokens=kw.get("max_tokens", 1024))
        return "".join(b.text for b in r.content if getattr(b, "type", None) == "text")

    def chat_tools(self, role, messages, tools, **kw):
        tier, model = self.model_for(role)
        r = self._create(tier, model, messages, tools=tools, max_tokens=kw.get("max_tokens", 1024))
        text = "".join(b.text for b in r.content if getattr(b, "type", None) == "text")
        tcs = [_ToolCall(b.id, b.name, json.dumps(b.input))
               for b in r.content if getattr(b, "type", None) == "tool_use"]
        finish = _STOP_MAP.get(getattr(r, "stop_reason", None), "tool_calls" if tcs else "stop")
        return _Resp([_Choice(_AsstMsg(text, tcs), finish)], _Usage(
            getattr(r.usage, "input_tokens", 0), getattr(r.usage, "output_tokens", 0)))


if __name__ == "__main__":  # self-check: the OpenAI<->Anthropic adapter (no network)
    # A realistic OpenAI-shape history: system, user, assistant-with-tool_call (our
    # shim, as the agent appends it), the tool result, then a follow-up user turn.
    asst = _AsstMsg("probing", [_ToolCall("call_1", "nmap", json.dumps({"target": "struts"}))])
    history = [
        {"role": "system", "content": "You are red."},
        {"role": "user", "content": "begin"},
        asst,
        {"role": "tool", "tool_call_id": "call_1", "content": "{\"open\": [8080]}"},
        {"role": "user", "content": "continue"},
    ]
    system, amsgs = to_anthropic_messages(history)
    assert system == "You are red.", system
    assert amsgs[0] == {"role": "user", "content": "begin"}, amsgs[0]
    # assistant turn carries a tool_use block
    use = amsgs[1]
    assert use["role"] == "assistant" and use["content"][1]["type"] == "tool_use", use
    assert use["content"][1]["name"] == "nmap" and use["content"][1]["input"] == {"target": "struts"}
    # tool result becomes a user turn with a tool_result block keyed by the call id
    res = amsgs[2]
    assert res["role"] == "user" and res["content"][0]["type"] == "tool_result", res
    assert res["content"][0]["tool_use_id"] == "call_1", res
    assert amsgs[3] == {"role": "user", "content": "continue"}, amsgs[3]

    tools = [{"type": "function", "function": {"name": "nmap", "description": "scan",
                                               "parameters": {"type": "object", "properties": {}}}}]
    at = to_anthropic_tools(tools)
    assert at == [{"name": "nmap", "description": "scan",
                   "input_schema": {"type": "object", "properties": {}}}], at
    print("provider_anthropic adapter ok")
