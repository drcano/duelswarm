"""Diverse-red arsenal + model-family panel, and the live service×family QD archive.

This module exists to make the co-evolution diversity go/no-go HONEST. The 54-cell
behavior archive in `swarm/population.py` has axes (entry-class, breadth, stealth,
depth) but NO axis for which T1 service was exploited or which attacker model family
drove the episode — so a Struts-only, single-family red (exactly what nulled the prior
arms race by homogenizing) spreads that archive trivially via its persona stub. The two
axes the diversity claim actually rests on live here:

  - SERVICE: which vetted T1 service was the entry exploit (struts / httpd / postgres /
    weblogic / gitlab / solr), i.e. which real MSF-grounded path red took.
  - FAMILY: which of the 5 resolved attacker model families (Phase-1 panel) ran it.

A genuinely diverse red fills many of the 6×5 = 30 service×family cells; a homogeneous
red collapses to a single cell. `LiveArsenalArchive` is the discriminating readout.

Grounding note: WHICH services a live range can actually present as the entry depends on
what is promoted to T1 in `config/vetted.json` (Docker+MSF, deploy-host). This module
records the axis so diversity is measurable; it does not itself boot or fire anything.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # runnable as script or -m

from swarm.lineage import Lineage
from swarm.msf import candidate_modules

# ── The resolved 5-family attacker panel ────────────────────────────────────────
# Token Factory checkpoints, pinned in docs/PREREGISTRATION.md §9 and used in the P1
# corpus (scripts/run_pilot.py / run_analysis.py import from here to stay in sync).
# nemotron uses the Super checkpoint actually run in the P1 corpus; PREREGISTRATION.md
# lists the Nano id for nemotron — the discrepancy is documented, the panel-of-record is
# what generated the corpus. Order is STABLE so family_bin is reproducible.
ATTACKER_PANEL = [
    "nvidia/nemotron-3-super-120b-a12b",
    "Qwen/Qwen3-30B-A3B-Instruct-2507",
    "deepseek-ai/DeepSeek-V4.1-Flash",
    "google/gemma-3-27b-it",
    "openai/gpt-oss-120b",
]

_LINEAGE = Lineage()

# The 5 families, in panel order (order-preserving dedup via the lineage graph).
ATTACKER_FAMILIES = []
for _m in ATTACKER_PANEL:
    _f = _LINEAGE.family_of(_m)
    if _f not in ATTACKER_FAMILIES:
        ATTACKER_FAMILIES.append(_f)

# ── The vetted T1 arsenal: service -> the CVE whose exploit red fires ────────────
# Order STABLE so service_bin is reproducible. MSF-backed services (struts/httpd/gitlab/
# solr) resolve a module via swarm.msf.SERVICE_MODULE_MAP; postgres/weblogic ground via
# hand-coded exploit_fn in swarm/live_weapon.py (COPY-PROGRAM / wls-wsat), so
# `module_for_service` returns None for them. struts/httpd/postgres/weblogic/gitlab are
# vetted T1 (config/vetted.json); solr is the promotion candidate.
ARSENAL_SERVICES = ["struts", "httpd", "postgres", "weblogic", "gitlab", "solr"]
SERVICE_CVE = {
    "struts":   "CVE-2017-5638",
    "httpd":    "CVE-2021-41773",
    "postgres": "CVE-2019-9193",
    "weblogic": "CVE-2017-10271",
    "gitlab":   "CVE-2021-22205",
    "solr":     "CVE-2021-44228",
}

LIVE_DESCRIPTOR_CELLS = len(ARSENAL_SERVICES) * len(ATTACKER_FAMILIES)  # 6 × 5 = 30


def cve_for_service(service):
    return SERVICE_CVE.get(service)


def service_for_cve(cve):
    """Reverse SERVICE_CVE; None for a CVE outside the arsenal (honest: not counted)."""
    for svc, c in SERVICE_CVE.items():
        if c == (cve or "").upper() or c == cve:
            return svc
    return None


def module_for_service(service):
    """The MSF module red fires for this service's CVE (first candidate), or None for a
    hand-coded service (postgres/weblogic). Ties the MSF-backed arsenal axis to the real
    gated MSF executor (swarm.msf.gated_msf_exploit)."""
    mods = candidate_modules(cve_for_service(service))
    return mods[0] if mods else None


def family_of(model_id):
    """Panel family for a model id, via the documented lineage graph."""
    return _LINEAGE.family_of(model_id)


def service_bin(service):
    if service not in ARSENAL_SERVICES:
        raise KeyError(f"service {service!r} not in ARSENAL_SERVICES")
    return ARSENAL_SERVICES.index(service)


def family_bin(model_id):
    fam = _LINEAGE.family_of(model_id)
    if fam not in ATTACKER_FAMILIES:
        raise KeyError(f"model {model_id!r} (family {fam!r}) not in the attacker panel")
    return ATTACKER_FAMILIES.index(fam)


def live_descriptor(service, model_id):
    """2-D service×family MAP-Elites cell. The honest diversity axes the 54-cell
    behavior archive lacks."""
    return (service_bin(service), family_bin(model_id))


class LiveArsenalArchive:
    """service×family behavior archive for the LIVE co-evolution loop: one elite per
    (service, family) cell, keeping the highest-fitness episode. `coverage` = occupied
    cells; `diversity` = coverage / 30. A diverse red climbs it; a homogeneous red sits
    at coverage 1 (`collapsed`)."""

    def __init__(self, cells=LIVE_DESCRIPTOR_CELLS):
        self.by_cell = {}          # (service_bin, family_bin) -> (fitness, meta)
        self.cells = cells

    def record(self, service, model_id, fitness, meta=None):
        """Insert an episode. Unmapped service/family are NOT counted (honest: an
        out-of-arsenal entry does not inflate diversity). Returns True if it entered."""
        try:
            cell = live_descriptor(service, model_id)
        except KeyError:
            return False
        prev = self.by_cell.get(cell)
        if prev is None or fitness > prev[0]:
            m = dict(meta or {})
            m.update({"service": service, "model": model_id})
            self.by_cell[cell] = (round(float(fitness), 4), m)
            return True
        return False

    def coverage(self):
        return len(self.by_cell)

    def diversity(self):
        return len(self.by_cell) / self.cells

    def collapsed(self):
        """A single-cell archive = red homogenized (the prior-run failure mode)."""
        return len(self.by_cell) <= 1

    def dump(self):
        return sorted(
            [{"cell": list(c), "service": m["service"], "model": m["model"],
              "fitness": f, "meta": {k: v for k, v in m.items()
                                     if k not in ("service", "model")}}
             for c, (f, m) in self.by_cell.items()],
            key=lambda e: e["cell"])

    def save(self, path):
        Path(path).write_text(json.dumps(
            {"cells": self.cells, "coverage": self.coverage(),
             "diversity": round(self.diversity(), 4), "entries": self.dump()}, indent=2))

    @classmethod
    def load(cls, path):
        blob = json.loads(Path(path).read_text())
        a = cls(cells=blob["cells"])
        for e in blob["entries"]:
            a.by_cell[tuple(e["cell"])] = (
                e["fitness"], {"service": e["service"], "model": e["model"], **e.get("meta", {})})
        return a


def _selftest():
    """Pure, offline: the archive DISCRIMINATES — a diverse red spreads it, a
    homogeneous (Struts-only, single-family) red collapses it to one cell. This is the
    honest go/no-go the 54-cell behavior archive cannot make (no service/family axis)."""
    assert ATTACKER_FAMILIES == ["nemotron", "qwen", "deepseek", "gemma", "gptoss"], ATTACKER_FAMILIES
    assert LIVE_DESCRIPTOR_CELLS == 30, LIVE_DESCRIPTOR_CELLS
    # Every arsenal service maps to a real CVE, and the vetted-T1 ones resolve an MSF module.
    for svc in ARSENAL_SERVICES:
        assert cve_for_service(svc), svc
    # MSF-backed services resolve a module; postgres/weblogic ground via hand-coded
    # exploit_fn in swarm/live_weapon.py (COPY-PROGRAM / wls-wsat), not MSF — None is honest.
    for svc in ("struts", "httpd", "gitlab", "solr"):
        assert module_for_service(svc), f"no MSF module for {svc}"
    for svc in ("postgres", "weblogic"):
        assert module_for_service(svc) is None, f"{svc} is hand-coded, not MSF"

    # DIVERSE red: cycle services × families -> fills many cells, does NOT collapse.
    div = LiveArsenalArchive()
    k = 0
    for svc in ARSENAL_SERVICES:
        for fam_model in ATTACKER_PANEL:
            div.record(svc, fam_model, fitness=0.5 + 0.01 * k)
            k += 1
    assert div.coverage() == 30 and not div.collapsed(), div.coverage()
    assert div.diversity() == 1.0, div.diversity()

    # HOMOGENEOUS red (the prior-run failure): Struts only, nemotron only -> ONE cell.
    homo = LiveArsenalArchive()
    for _ in range(12):
        homo.record("struts", "nvidia/nemotron-3-super-120b-a12b", fitness=0.6)
    assert homo.coverage() == 1 and homo.collapsed(), homo.coverage()
    assert homo.diversity() == round(1 / 30, 4) or homo.diversity() == 1 / 30, homo.diversity()

    # A partially-diverse red (3 services × 2 families) spreads past collapse but not full.
    part = LiveArsenalArchive()
    for svc in ARSENAL_SERVICES[:3]:
        for fam_model in ATTACKER_PANEL[:2]:
            part.record(svc, fam_model, fitness=0.7)
    assert part.coverage() == 6 and not part.collapsed(), part.coverage()

    # Out-of-arsenal entry is NOT counted (no diversity inflation).
    assert part.record("mailserver", ATTACKER_PANEL[0], 0.9) is False

    # save/load round-trips the frontier.
    import tempfile
    p = Path(tempfile.mkdtemp()) / "arsenal.json"
    div.save(p)
    assert LiveArsenalArchive.load(p).coverage() == 30

    print(f"arsenal ok: {len(ATTACKER_FAMILIES)} families × {len(ARSENAL_SERVICES)} "
          f"services = {LIVE_DESCRIPTOR_CELLS} cells; diverse red spreads to 30/30, "
          f"homogeneous red collapses to 1/30 (go/no-go discriminates)")


if __name__ == "__main__":
    _selftest()
