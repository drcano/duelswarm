"""Model lineage graph + genealogical proximity metric (RESEARCH_BRIEF §3).

The lineage-blindspot hypothesis is tested as an *interaction*: does a monitor's
detection failure rise with genealogical proximity to the attacker it is judging?
That needs proximity to be a real, documented, auditable number — not folklore.
This module loads the provenance graph (config/lineage.yaml) and resolves a
`proximity(attacker, monitor)` scalar used as the key predictor in the
mixed-effects model (scripts/analyze_lineage.py).

Everything here is deterministic and offline (no API, no credits).
"""
from pathlib import Path

import yaml

_CONFIG = Path(__file__).resolve().parent.parent / "config" / "lineage.yaml"


class Lineage:
    def __init__(self, config_path=_CONFIG):
        cfg = yaml.safe_load(Path(config_path).read_text())
        self.families = cfg["families"]
        # (frozenset{a,b}) -> proximity, symmetric.
        self._rel = {}
        for r in cfg.get("relations") or []:
            a, b = r["pair"]
            self._rel[frozenset((a, b))] = float(r["proximity"])

    def family_of(self, model_id):
        """Map a (possibly vendor-prefixed) model id to its lineage family.

        First alias that is a case-insensitive substring wins; families are
        scanned most-specific-first as declared in the YAML."""
        mid = (model_id or "").lower()
        for fam, meta in self.families.items():
            for alias in meta["aliases"]:
                if alias.lower() in mid:
                    return fam
        return None

    def proximity(self, a, b):
        """Genealogical proximity ∈ [0, 1] between two models (ids or families).

        1.0 if the same family, a documented cross-family edge if one exists,
        else 0.0. Raises if either model's family can't be identified — an
        unknown attacker/monitor must never silently score as 'distant'."""
        fa = a if a in self.families else self.family_of(a)
        fb = b if b in self.families else self.family_of(b)
        if fa is None or fb is None:
            raise ValueError(f"unknown lineage for {a!r} (->{fa}) or {b!r} (->{fb})")
        if fa == fb:
            return 1.0
        return self._rel.get(frozenset((fa, fb)), 0.0)


if __name__ == "__main__":  # self-check: families resolve, metric is as documented
    L = Lineage()
    assert L.family_of("nvidia/Nemotron-3-Ultra-550b-a55b") == "nemotron"
    assert L.family_of("meta-llama/Llama-3.1-70B-Instruct") == "llama"
    assert L.family_of("Qwen/Qwen2.5-72B-Instruct") == "qwen"
    assert L.family_of("deepseek-ai/DeepSeek-V3") == "deepseek"
    assert L.family_of("mistralai/Mistral-Small-Instruct") == "mistral"
    assert L.family_of("google/gemma-3-27b-it") == "gemma"
    assert L.family_of("openai/gpt-oss-120b") == "gptoss"
    assert L.family_of("claude-opus-5-5") == "claude"
    assert L.family_of("something/unknown-7b") is None

    assert L.proximity("qwen", "qwen") == 1.0                       # same lineage
    assert L.proximity("nemotron", "llama") == 0.5                  # documented (dormant: no Llama served)
    assert L.proximity("deepseek", "qwen") == 0.0                   # resolved: native DeepSeek-V4, not a distill
    assert L.proximity("qwen", "mistral") == 0.0                    # independent
    assert L.proximity("gemma", "gptoss") == 0.0                    # resolved panel: independent
    assert L.proximity("claude", "nemotron") == 0.0                 # frontier vs open
    # symmetric + id-level resolution
    assert L.proximity("Qwen/Qwen2.5-72B", "qwen") == 1.0
    assert L.proximity("meta-llama/Llama-3.1-70B", "nvidia/Nemotron-3-Super") == 0.5
    try:
        L.proximity("mystery-model", "qwen")
        raise SystemExit("expected ValueError for unknown family")
    except ValueError:
        pass
    print("lineage ok: families resolve, proximity matches documented graph")
