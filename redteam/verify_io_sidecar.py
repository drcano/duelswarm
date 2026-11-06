"""Cold re-derivation of the full per-turn I/O sidecar (Task 1), trusting neither agent.

The live engine persists red's EXACT per-turn cognition — the system prompt (once, by hash), the
user prompt it was conditioned on, its full raw completion (reasoning included), the parsed action,
and the exact tool result it received — into a hash-chained SIDECAR (`<chain>_io.jsonl`). Every
sidecar entry is PINNED into the main chain as an `io.record` carrying that entry's seq+hash.

This auditor re-derives, with the stdlib only (no swarm import, like reverify_floor), that:
  1. the sidecar chain itself verifies (prev-linkage + per-entry hash);
  2. the main chain verifies;
  3. EVERY sidecar entry is pinned by a matching `io.record` in the main chain (forward), AND
     every `io.record` pin resolves to a sidecar entry whose hash matches (reverse) — so a sidecar
     tamper breaks (1)+the hash pin, and a sidecar tail-truncation/deletion leaves a dangling pin
     the reverse check catches (the main chain's own count/final-hash is externally anchored);
  4. the record is COMPLETE: a one-time header carries the full system prompt matching its sha, and
     every turn record carries the user prompt + raw completion (or a recorded veto/timeout/error).

A pure-log reader can thus reproduce red's cognition and confirm it was neither edited nor pruned.
"""
import sys
import json
import hashlib
from pathlib import Path

GENESIS = "0" * 64


def _hash(prev, payload):
    """Byte-identical to swarm.eventlog._hash: sha256(prev + canonical(entry-minus-hash))."""
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev + body).encode()).hexdigest()


def _load(path):
    p = Path(path)
    if not p.exists():
        return None
    return [json.loads(ln) for ln in p.read_text().splitlines() if ln.strip()]


def _walk(entries):
    """Re-walk prev-linkage + per-entry hash. Returns (ok, first_bad_seq_or_None)."""
    prev = GENESIS
    for e in entries:
        recomputed = _hash(prev, {k: e[k] for k in e if k != "hash"})
        if e.get("prev") != prev or recomputed != e.get("hash"):
            return False, e.get("seq")
        prev = e["hash"]
    return True, None


def verify(main_path, io_path):
    main = _load(main_path)
    io = _load(io_path)
    out = {"main_path": str(main_path), "io_path": str(io_path),
           "main_present": main is not None, "io_present": io is not None}
    if main is None or io is None:
        out["ok"] = False
        out["reason"] = "missing log" if main is None else "missing io sidecar"
        return out

    main_ok, main_bad = _walk(main)
    io_ok, io_bad = _walk(io)
    out.update(main_chain_verified=main_ok, main_first_bad=main_bad,
               io_chain_verified=io_ok, io_first_bad=io_bad)

    # pins on the main chain: io_seq -> io_hash (as the main chain recorded them)
    pins = {}
    dup_pins = []
    for e in main:
        if e.get("action") != "io.record":
            continue
        d = e.get("data") or {}
        s = d.get("io_seq")
        if s in pins:
            dup_pins.append(s)
        pins[s] = d.get("io_hash")

    # sidecar entries, keyed by their own seq+recorded hash
    io_by_seq = {e.get("seq"): e for e in io}

    # (forward) every sidecar entry must be pinned with a matching hash
    unpinned = [e.get("seq") for e in io
                if e.get("seq") not in pins or pins[e.get("seq")] != e.get("hash")]
    # (reverse) every pin must resolve to a present sidecar entry with a matching hash
    dangling = [s for s, h in pins.items()
                if s not in io_by_seq or io_by_seq[s].get("hash") != h]

    # completeness of the captured cognition
    headers = [e for e in io if (e.get("data") or {}).get("kind") == "header"]
    header_ok = False
    if headers:
        hd = headers[0].get("data") or {}
        sysp = hd.get("system_prompt")
        header_ok = bool(sysp) and _sha256(sysp) == hd.get("system_prompt_sha256")
    turns = [e for e in io if (e.get("data") or {}).get("kind") == "turn"]
    turns_full = 0
    thin = []
    for e in turns:
        d = e.get("data") or {}
        has_prompt = bool(d.get("user_prompt"))
        # a turn must carry what red was conditioned on and SOME record of the model exchange:
        # a raw completion, or an explicit veto/timeout/error that explains its absence.
        has_io = ("raw_completion" in d or "error" in d
                  or (d.get("parsed") or {}).get("veto")
                  or (d.get("tool_result") or {}).get("turn_timeout"))
        if has_prompt and has_io:
            turns_full += 1
        else:
            thin.append(d.get("turn"))

    out.update(pins=len(pins), io_entries=len(io), unpinned=unpinned, dangling=dangling,
               duplicate_pins=dup_pins, header_ok=header_ok, turns=len(turns),
               turns_full=turns_full, thin_turns=thin)
    out["ok"] = bool(main_ok and io_ok and not unpinned and not dangling
                     and not dup_pins and header_ok and not thin and len(io) > 0)
    return out


def _sha256(s):
    return hashlib.sha256((s or "").encode()).hexdigest()


# ── selftest: build a matched main+sidecar pair with the eventlog recipe; PASS clean, BITE on tamper ──
def _selftest():
    import tempfile

    def writer(path):
        """A minimal, independent EventLog-compatible appender (same hash recipe)."""
        entries = []
        last = [GENESIS]

        def append(actor, action, data, on_append=None):
            payload = {"seq": len(entries), "ts": 0.0, "actor": actor, "action": action,
                       "data": data or {}, "prev": last[0]}
            payload["hash"] = _hash(last[0], payload)
            with open(path, "a") as f:
                f.write(json.dumps(payload, sort_keys=True) + "\n")
            entries.append(payload)
            last[0] = payload["hash"]
            if on_append:
                on_append(payload)
            return payload
        return append, entries

    d = Path(tempfile.mkdtemp())
    main_p, io_p = d / "chain.jsonl", d / "chain_io.jsonl"
    main_append, _ = writer(main_p)
    # the sidecar pins each entry into the main chain exactly as the driver wires it
    io_append, _ = writer(io_p)

    def io(actor, data):
        io_append(actor, "io.turn" if data.get("kind") == "turn" else "io.header", data,
                  on_append=lambda e: main_append(
                      "system", "io.record",
                      {"io_seq": e["seq"], "io_hash": e["hash"], "sidecar": io_p.name,
                       "turn": (e["data"] or {}).get("turn"), "kind": (e["data"] or {}).get("kind")}))

    main_append("system", "config", {"run": "selftest"})
    io("red", {"kind": "header", "turn": -1, "actor": "red",
               "system_prompt": "SYS PROMPT", "system_prompt_sha256": _sha256("SYS PROMPT")})
    for t in range(3):
        io("red", {"kind": "turn", "turn": t, "actor": "red",
                   "system_prompt_sha256": _sha256("SYS PROMPT"),
                   "user_prompt": f"obs at turn {t}", "raw_completion": f"<think>…</think> act {t}",
                   "parsed": {"tool": "scan", "args": {}, "thought": "x"},
                   "tool_result": {"hosts": []}})
    clean = verify(main_p, io_p)
    assert clean["ok"], ("clean pair must verify", clean)
    assert clean["turns_full"] == 3 and clean["header_ok"], clean

    # (a) tamper a sidecar entry's content -> io chain breaks AND its pin no longer matches
    lines = io_p.read_text().splitlines()
    rec = json.loads(lines[2]); rec["data"]["raw_completion"] = "FORGED"
    lines[2] = json.dumps(rec, sort_keys=True)
    bad_a = d / "io_tampered.jsonl"; bad_a.write_text("\n".join(lines) + "\n")
    va = verify(main_p, bad_a)
    assert not va["ok"] and (not va["io_chain_verified"] or va["unpinned"]), ("tamper must bite", va)

    # (b) drop the LAST sidecar entry but keep its pin on the main chain -> dangling pin
    bad_b = d / "io_truncated.jsonl"
    bad_b.write_text("\n".join(io_p.read_text().splitlines()[:-1]) + "\n")
    vb = verify(main_p, bad_b)
    assert not vb["ok"] and vb["dangling"], ("tail-truncation must leave a dangling pin", vb)

    # (c) rewrite a pin's io_hash on the main chain -> main chain breaks (hash stale) + forward mismatch
    mlines = main_p.read_text().splitlines()
    for i, ln in enumerate(mlines):
        r = json.loads(ln)
        if r["action"] == "io.record":
            r["data"]["io_hash"] = "0" * 64
            mlines[i] = json.dumps(r, sort_keys=True)
            break
    bad_c = d / "main_tampered.jsonl"; bad_c.write_text("\n".join(mlines) + "\n")
    vc = verify(bad_c, io_p)
    assert not vc["ok"] and (not vc["main_chain_verified"] or vc["unpinned"]), ("pin tamper must bite", vc)

    print("verify_io_sidecar selftest ok "
          f"(clean turns_full={clean['turns_full']}; tamper/truncate/pin-edit all bite)")


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if "--selftest" in sys.argv:
        _selftest()
    elif len(args) >= 1:
        main_path = args[0]
        io_path = args[1] if len(args) >= 2 else str(Path(main_path).with_name(
            Path(main_path).stem + "_io.jsonl"))
        res = verify(main_path, io_path)
        print(json.dumps(res, indent=2, sort_keys=True))
        sys.exit(0 if res.get("ok") else 1)
    else:
        print("usage: verify_io_sidecar.py <main_chain.jsonl> [<chain_io.jsonl>] | --selftest")
        sys.exit(2)
