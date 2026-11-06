"""The boot-clean rule (LIQUID_BUILD_MASTER A1) — `vetted:true` is EARNED, not set.

A host may be tier **T1** (eligible to be a REAL compromise) ONLY if its image is
in the vetted registry (`config/vetted.json`). An image enters that registry ONLY
through `record_proof`, which demands, in order:

  1. BOOT evidence   — the real container came up and its service was reachable
                       on THIS hardware (captured, hashed).
  2. EXPLOIT evidence — real output from firing the CVE's own primitive against the
                       booted container (uid=…, file contents, command output) that
                       `validate_finding` (the XBOW gate) grounds. A model merely
                       *claiming* a pop is refused here and promotes NOTHING.
  3. A pinned upstream Vulhub commit for vendored CVEs (provenance).

Every step is appended to a hash-chained proof log (`config/vetting_proof.jsonl`),
so a promotion is tamper-evident: `verify()` re-walks it, or a reviewer re-boots to
reproduce. NO grandfathering — struts/jenkins/db earn their T1 the same way a new
Vulhub add does. Partial promotion (some images refused) is the correct, honest
outcome, never a faked flag.

`range_gen` reads `is_vetted(image)` as the authoritative boot-clean rule; the live
Docker vetting that fills the registry lives in `scripts/vet_pool.py`.
"""
import json
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from swarm.eventlog import EventLog
from swarm.polymorph import validate_finding

_ROOT = Path(__file__).resolve().parent.parent
REGISTRY = _ROOT / "config" / "vetted.json"
PROOF_LOG = _ROOT / "config" / "vetting_proof.jsonl"   # committable (data/ is gitignored)


def _sha(s):
    return hashlib.sha256((s or "").encode()).hexdigest()


def load_registry(path=REGISTRY):
    p = Path(path)
    return json.loads(p.read_text()) if p.exists() else {}


def is_vetted(image, path=REGISTRY):
    """The boot-clean rule: True iff `image` has a recorded hash-chained proof."""
    return image in load_registry(path)


def vetted_images(path=REGISTRY):
    return sorted(load_registry(path))


class NotExploitable(RuntimeError):
    """Raised when exploit evidence does not ground the claim — promotes NOTHING."""


def record_proof(image, cve, boot_evidence, exploit_evidence, *, kind="rce",
                 vulhub_commit=None, note=None, registry=REGISTRY, proof_log=PROOF_LOG):
    """Append a hash-chained boot+exploit proof and promote `image` to vetted.

    Raises `NotExploitable` (and promotes nothing) when `exploit_evidence` fails
    `validate_finding` — the honesty gate that keeps a stub or a hallucinated pop
    out of the T1 pool. Returns the registry record on success."""
    log = EventLog(proof_log)
    log.append("vetter", "vet.boot",
               {"image": image, "cve": cve, "boot_evidence": (boot_evidence or "")[:500],
                "boot_sha256": _sha(boot_evidence)})
    verdict = validate_finding({"output": exploit_evidence}, log.entries(), kind)
    log.append("vetter", "vet.exploit",
               {"image": image, "cve": cve, "kind": kind,
                "evidence": (exploit_evidence or "")[:1000],
                "evidence_sha256": _sha(exploit_evidence),
                "valid": verdict["valid"], "reason": verdict["reason"]})
    if not verdict["valid"]:
        log.append("vetter", "vet.refused",
                   {"image": image, "cve": cve, "reason": verdict["reason"]})
        raise NotExploitable(f"{image} ({cve}) refused: {verdict['reason']}")
    promote = log.append("vetter", "vet.promote",
                         {"image": image, "cve": cve, "vulhub_commit": vulhub_commit,
                          "evidence_sha256": _sha(exploit_evidence), "note": note})
    reg = load_registry(registry)
    reg[image] = {"cve": cve, "kind": kind, "vulhub_commit": vulhub_commit,
                  "boot_sha256": _sha(boot_evidence),
                  "exploit_sha256": _sha(exploit_evidence),
                  "proof_seq": promote["seq"], "proof_hash": promote["hash"],
                  "vetted_at": promote["ts"], "note": note}
    Path(registry).write_text(json.dumps(reg, indent=2, sort_keys=True) + "\n")
    return reg[image]


if __name__ == "__main__":  # self-check: proof earns promotion; a bare claim is refused
    import tempfile

    d = Path(tempfile.mkdtemp())
    reg, proof = d / "vetted.json", d / "proof.jsonl"

    # A grounded pop (real uid= output) is promoted and recorded with a proof hash.
    rec = record_proof("img/real:1", "CVE-2017-5638",
                       boot_evidence="HTTP 302 on :8080; Tomcat up",
                       exploit_evidence="uid=0(root) gid=0(root) groups=0(root)",
                       kind="rce", vulhub_commit="deadbeef", registry=reg, proof_log=proof)
    assert rec["proof_hash"] and rec["cve"] == "CVE-2017-5638", rec
    assert is_vetted("img/real:1", reg) and "img/real:1" in vetted_images(reg)

    # The boot-clean rule gates an unrecorded image.
    assert not is_vetted("img/never:1", reg)

    # A bare claim with no RCE indicator is REFUSED — nothing is promoted (the A0
    # honesty bar, one layer up: a stub can't buy its way into T1).
    try:
        record_proof("img/fake:1", "CVE-0000-0000",
                     boot_evidence="container up",
                     exploit_evidence="I rooted the box, trust me",
                     kind="rce", registry=reg, proof_log=proof)
        raise SystemExit("a bare claim was promoted — honesty gate failed")
    except NotExploitable:
        pass
    assert not is_vetted("img/fake:1", reg), "refused image must not be vetted"

    # The proof log is a tamper-evident chain and the refusal is on it.
    log = EventLog(proof)
    ok, bad = log.verify()
    assert ok, ("proof chain broken", bad)
    acts = [e["action"] for e in log.entries()]
    assert "vet.promote" in acts and "vet.refused" in acts, acts
    print(f"vetting ok: 1 promoted (hash-chained proof), 1 refused (bare claim); "
          f"boot-clean rule gates T1; proof chain verified ({len(acts)} events)")
