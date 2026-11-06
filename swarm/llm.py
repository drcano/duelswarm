"""Provider client wrapper (SPEC §2, §4).

One provider per run. The run witnesses its provider + model lineage in the hash
chain at start (a `provider.pinned` system event), and the host guard below refuses
any model call whose base_url host does not match the pinned host regex — a mid-run
provider swap is caught at the API boundary and raised. Any configured provider
(Nebius Token Factory, Anthropic, a local OpenAI-compatible server) is valid; what is
forbidden is a SILENT swap. Routing is config-driven (models.yaml) so models are
swappable without code changes; a UsageCounter tracks the live cost/latency figures.
"""
import os
import re
import time
from pathlib import Path
from urllib.parse import urlparse

import yaml
from openai import OpenAI

_CONFIG = Path(__file__).resolve().parent.parent / "config" / "models.yaml"
# Output-token budgets are per-tier and live in config/models.yaml (tiers.<t>.max_tokens),
# read at runtime. There is NO hardcoded clamp in code: a tier with no configured budget
# is sent with whatever max_tokens the caller passed (or none). Reasoning tiers need a
# generous budget or they emit empty content — so set it in config, visibly, not in code.


def _pin_regex_for(base_url):
    """The host pin for a run: derived from the configured base_url's registrable domain
    (api.x.nebius.com -> (^|\\.)nebius\\.com$), so pinning ANY provider works the same way.
    PINNED_HOST_REGEX overrides it for ad-hoc/offline tests."""
    env = os.environ.get("PINNED_HOST_REGEX")
    if env:
        return env
    host = (urlparse(base_url).hostname or "").lower()
    labels = [l for l in host.split(".") if l]
    domain = ".".join(labels[-2:]) if len(labels) >= 2 else host
    return (r"(^|\.)" + re.escape(domain) + r"$") if domain else r".*"


def _assert_pinned_host(base_url, pinned_host_regex):
    """Refuse a model call whose base_url host does not match the run's pinned host regex.
    One provider per run: the provider is pinned in the hash chain at start (provider.pinned)
    and may not change mid-run — a swap is caught here, at the API boundary, and raised."""
    host = (urlparse(base_url).hostname or "").lower()
    if not re.search(pinned_host_regex, host):
        raise RuntimeError(
            f"mid-run provider swap at base_url {base_url!r} (host {host!r}) vs pinned host "
            f"regex {pinned_host_regex!r}. One provider per run — the provider is pinned in the "
            "hash chain at start and may not change mid-run."
        )


def _provider_label(host):
    """A short provider name from the host's registrable domain: api.x.nebius.com -> 'nebius',
    api.anthropic.com -> 'anthropic', localhost/127.0.0.1 -> 'local'."""
    if host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost"):
        return "local"
    labels = [l for l in host.split(".") if l]
    return labels[-2] if len(labels) >= 2 else (host or "unknown")


def resolved_provider(config_path=None):
    """The provider base_url/host make_router WOULD use, the derived host pin, whether the host guard
    is active, whether the configured host matches the pin, and the model lineage. Pure config/env
    read — NO client, NO API call — so a run can WITNESS its provider in the hash chain
    (`provider.pinned`) and a verifier can re-derive WHICH provider from the chain instead of trusting
    in-code. base_url carries no secret (the API key is a separate env var), so it is safe to log."""
    cfg = yaml.safe_load(Path(config_path or _CONFIG).read_text())
    base_url = os.environ.get("NEBIUS_BASE_URL") or cfg.get("provider", {}).get("base_url", "")
    host = (urlparse(base_url).hostname or "").lower()
    pin = _pin_regex_for(base_url)
    lineage = {t: (v or {}).get("model") for t, v in (cfg.get("tiers", {}) or {}).items()}
    return {"base_url": base_url, "host": host, "provider": _provider_label(host),
            "pinned_host_regex": pin, "pinned_host_guard_active": pin != r".*",
            "pinned_host_match": bool(re.search(pin, host)), "model_lineage": lineage}


_COST_PER_1K = {
    "ultra": {"prompt": 0.012, "completion": 0.036},
    "super": {"prompt": 0.003, "completion": 0.009},
    "nano":  {"prompt": 0.0003, "completion": 0.0009},
}


class UsageCounter:
    """Live cost/latency counter across tiers (SPEC §4)."""

    def __init__(self):
        self.calls = []

    def record(self, tier, model, latency_s, usage, max_tokens=None):
        self.calls.append({
            "tier": tier,
            "model": model,
            "latency_s": latency_s,
            "prompt_tokens": getattr(usage, "prompt_tokens", 0) if usage else 0,
            "completion_tokens": getattr(usage, "completion_tokens", 0) if usage else 0,
            "max_tokens": max_tokens,
        })

    def summary(self):
        out = {}
        for c in self.calls:
            t = out.setdefault(c["tier"], {
                "calls": 0, "latency_s": 0.0,
                "prompt_tokens": 0, "completion_tokens": 0,
                "cost_usd": 0.0, "max_tokens": 0,
            })
            t["calls"] += 1
            t["latency_s"] += c["latency_s"]
            t["prompt_tokens"] += c["prompt_tokens"]
            t["completion_tokens"] += c["completion_tokens"]
            t["max_tokens"] = max(t["max_tokens"], c.get("max_tokens") or 0)
            rates = _COST_PER_1K.get(c["tier"], _COST_PER_1K["super"])
            t["cost_usd"] += (c["prompt_tokens"] * rates["prompt"]
                              + c["completion_tokens"] * rates["completion"]) / 1000
        return out

    def total_cost(self):
        return sum(t.get("cost_usd", 0) for t in self.summary().values())


class LLMError(RuntimeError):
    """A Token Factory call failed terminally (after the SDK's own retries).

    Raised with tier/model context so the live duel can degrade gracefully
    (fall back to scripted for that step) instead of crashing mid-run."""


class EmptyReply(LLMError):
    """A live call returned no usable text — an integrity failure, not a
    transient one. A hollow "live" reply must fail loud, never be logged as
    `reply: ""` and counted as a real Nemotron call (LIQUID_REALISM P0)."""


def _content_of(message):
    """Assistant text, tolerant of reasoning-model response shapes.

    Nemotron reasoning tiers (Super/Ultra) may put the answer in `content`, or
    leave `content` empty and carry text in `reasoning_content`/`reasoning` — and
    a too-small `max_tokens` truncates before any `content` is emitted at all.
    Prefer real content; fall back to the reasoning field so a live call that
    did return tokens is not mistaken for empty."""
    content = (getattr(message, "content", None) or "").strip()
    if content:
        return content
    for attr in ("reasoning_content", "reasoning"):
        alt = (getattr(message, attr, None) or "").strip()
        if alt:
            return alt
    return ""


class Router:
    """Resolves role -> tier -> model and calls Token Factory (OpenAI-compatible).

    Hardened for the live path (brief §3): every request carries a timeout, and
    transient failures (429/5xx/connection/timeout) are retried with backoff by
    the OpenAI SDK (max_retries). A terminal failure raises LLMError so callers
    can fall back to scripted rather than crash.
    """

    def __init__(self, config_path=_CONFIG, on_call=None, timeout=None, max_retries=None,
                 force_model=None):
        # force_model overrides every role's model with one checkpoint — used by the
        # Phase-1 corpus/matrix runners to point red (or a monitor) at a chosen
        # open-family model without touching models.yaml. Tier labels (and their
        # cost rates) are kept, so forced-Nemotron cost stays accurate; for other
        # families report tokens (the hard number) rather than the tier-rate $.
        self.force_model = force_model
        self.cfg = yaml.safe_load(Path(config_path).read_text())
        provider = self.cfg.get("provider", {})
        base_url = os.environ.get("NEBIUS_BASE_URL") or provider["base_url"]
        self.pinned_host_regex = _pin_regex_for(base_url)
        _assert_pinned_host(base_url, self.pinned_host_regex)
        key_env = provider["api_key_env"]
        key = os.environ.get(key_env)
        if not key:
            raise RuntimeError(f"{key_env} is not set (see .env.example)")
        # Timeout/retries: arg > env > config > default. SDK handles backoff + Retry-After.
        self.timeout = float(timeout if timeout is not None
                             else os.environ.get("NEBIUS_TIMEOUT_S", provider.get("timeout_s", 60)))
        self.max_retries = int(max_retries if max_retries is not None
                               else os.environ.get("NEBIUS_MAX_RETRIES", provider.get("max_retries", 4)))
        self.client = OpenAI(base_url=base_url, api_key=key,
                             timeout=self.timeout, max_retries=self.max_retries)
        self.usage = UsageCounter()
        self._on_call = on_call

    def model_for(self, role):
        return _resolve(self.cfg, role, self.force_model)

    def _emit(self, tier, model, latency, usage, max_tokens=None):
        self.usage.record(tier, model, latency, usage, max_tokens=max_tokens)
        if self._on_call:
            try:
                self._on_call({
                    "tier": tier, "model": model.split("/")[-1],
                    "latency_s": round(latency, 2),
                    "prompt_tokens": getattr(usage, "prompt_tokens", 0) if usage else 0,
                    "completion_tokens": getattr(usage, "completion_tokens", 0) if usage else 0,
                    "max_tokens": max_tokens,
                })
            except Exception:
                pass

    def _tier_budget(self, tier):
        """Per-tier output budget from config/models.yaml (tiers.<tier>.max_tokens), or
        None if the config sets none. No code-level default: config is the only source."""
        per_tier = (self.cfg.get("tiers", {}).get(tier, {}) or {}).get("max_tokens")
        return int(per_tier) if per_tier else None

    def _create(self, tier, model, **params):
        """One create() call with timing + typed error translation. The per-tier config
        budget is a FLOOR a caller may raise but never silently shrink; with no configured
        budget, the caller's own max_tokens is passed through unchanged. The applied
        max_tokens is logged so truncation is visible."""
        budget = self._tier_budget(tier)
        caller = int(params.get("max_tokens") or 0)
        applied = max(caller, budget) if budget else (caller or None)
        if applied:
            params["max_tokens"] = applied
        t0 = time.monotonic()
        try:
            resp = self.client.chat.completions.create(model=model, **params)
        except Exception as e:  # SDK already retried transient errors before raising
            raise LLMError(f"{tier}/{model} call failed after retries: {e}") from e
        self._emit(tier, model, time.monotonic() - t0, resp.usage, max_tokens=applied)
        return resp

    def chat(self, role, messages, **kw):
        tier, model = self.model_for(role)
        resp = self._create(tier, model, messages=messages, **kw)
        return _content_of(resp.choices[0].message)

    def chat_tools(self, role, messages, tools, **kw):
        tier, model = self.model_for(role)
        return self._create(tier, model, messages=messages, tools=tools, **kw)


def _resolve(cfg, role, force_model=None):
    """Pure role -> (tier, model) resolution. force_model overrides the tier's model (the
    model the Router actually sends). The ONE place this logic lives, shared by
    Router.model_for (the live path) and resolve_model (offline metadata) so a label and the
    router can never drift."""
    tier = cfg["roles"].get(role, role)
    if force_model:
        return tier, force_model
    return tier, cfg["tiers"][tier]["model"]


def resolve_model(role, *, force_model=None, config_path=_CONFIG):
    """Resolve role -> (tier, model) from config WITHOUT a client (offline, no API key), so a
    metadata writer can record the model a role will actually invoke — identical to what the
    Router resolves. Basename the model (`model.split('/')[-1]`) to match the llm.call record
    (Router._emit logs the basename)."""
    return _resolve(yaml.safe_load(Path(config_path).read_text()), role, force_model)


def make_router(provider=None, **kw):
    """Return a Router for the chosen provider. One provider per run: the run pins its provider in
    the hash chain (`provider.pinned`) and the host guard refuses a mid-run swap. 'nebius' (default)
    is Nemotron via Token Factory; 'anthropic' is the Claude lane (swarm/provider_anthropic.py);
    'local' (a local OpenAI-compatible server) is not wired yet. A run on a non-default provider is
    a separate, PRE-REGISTERED experiment arm, never silently mixed with Nebius results."""
    provider = (provider or "nebius").lower()
    if provider == "anthropic":
        from swarm.provider_anthropic import AnthropicRouter
        return AnthropicRouter(**kw)
    if provider == "local":
        raise RuntimeError("provider 'local' is not wired yet (swarm/provider_local.py). "
                           "Use 'nebius' (default) or 'anthropic'.")
    return Router(**kw)  # force_model passes through via **kw


if __name__ == "__main__":  # self-check: provider pin guard + live-path hardening (no network)
    # Pin derived from the configured host; the matching host passes, a mid-run swap raises.
    _neb = _pin_regex_for("https://api.tokenfactory.nebius.com/v1/")
    assert _neb == r"(^|\.)nebius\.com$", _neb      # Nebius behavior byte-identical to before
    _assert_pinned_host("https://api.tokenfactory.nebius.com/v1/", _neb)
    _assert_pinned_host("https://api.tokenfactory.us-central1.nebius.com/v1/", _neb)
    try:
        _assert_pinned_host("https://api.anthropic.com/v1/", _neb)
        raise SystemExit("guard failed to block a mid-run provider swap")
    except RuntimeError:
        pass
    # The pin GENERALIZES: an Anthropic base_url pins to anthropic, which then rejects a Nebius host.
    _ant = _pin_regex_for("https://api.anthropic.com/v1/")
    _assert_pinned_host("https://api.anthropic.com/v1/", _ant)
    try:
        _assert_pinned_host("https://api.tokenfactory.nebius.com/v1/", _ant)
        raise SystemExit("anthropic pin wrongly accepted a Nebius host")
    except RuntimeError:
        pass
    # PINNED_HOST_REGEX overrides the derived pin for ad-hoc/offline tests.
    os.environ["PINNED_HOST_REGEX"] = r".*"
    _assert_pinned_host("https://example.invalid/v1/", _pin_regex_for("https://anything/"))
    del os.environ["PINNED_HOST_REGEX"]

    # Router applies timeout + retries to the client (brief §3). Dummy key, no network.
    os.environ["NEBIUS_API_KEY"] = os.environ.get("NEBIUS_API_KEY", "sk-test")
    r = Router(timeout=12, max_retries=7)
    assert r.timeout == 12 and r.max_retries == 7, (r.timeout, r.max_retries)
    assert float(r.client.timeout) == 12, r.client.timeout
    assert r.client.max_retries == 7, r.client.max_retries
    # Terminal failures surface as LLMError with tier/model context.
    def _boom(*a, **k):
        raise RuntimeError("connection reset")
    r.client.chat.completions.create = _boom
    try:
        r.chat("red.attack", [{"role": "user", "content": "hi"}])
        raise SystemExit("expected LLMError")
    except LLMError as e:
        assert "super" in str(e), str(e)  # red.attack -> super tier

    # P0: content extraction tolerates reasoning-model shapes (no network).
    class _Msg:
        def __init__(self, content=None, reasoning_content=None, reasoning=None):
            self.content, self.reasoning_content, self.reasoning = (
                content, reasoning_content, reasoning)
    assert _content_of(_Msg(content="  hello ")) == "hello"
    assert _content_of(_Msg(content="", reasoning_content="  thought ")) == "thought"
    assert _content_of(_Msg(content=None, reasoning="deep")) == "deep"
    assert _content_of(_Msg(content="answer", reasoning_content="ignore me")) == "answer"
    assert _content_of(_Msg()) == ""   # truly empty -> callers must fail loud
    print("provider pin guard ok (derived + generalizes + swap raises); "
          "timeout/retries/LLMError ok; reasoning-content extraction ok")
