"""Smoke test: one real Nemotron call through Nebius Token Factory (SPEC §2).

Proves the runtime call goes to Token Factory, not HF/OpenRouter. Needs
NEBIUS_API_KEY set. Run:  python scripts/smoke_test.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from dotenv import load_dotenv
load_dotenv()
from swarm.llm import Router


def main():
    r = Router()
    base = str(r.client.base_url)
    print("base_url:", base)
    assert "nebius.com" in base, "NOT a Token Factory host — would be a disqualifier"

    tier, model = r.model_for("blue.triage")   # Nano
    print(f"calling tier={tier} model={model} ...")
    out = r.chat(
        "blue.triage",
        [{"role": "user", "content": "Reply with exactly: DUELSWARM OK"}],
        max_tokens=16,
        temperature=0,
    )
    print("response:", out)
    print("usage:", r.usage.summary())
    print("OK — runtime call went through Nebius Token Factory.")


if __name__ == "__main__":
    main()
