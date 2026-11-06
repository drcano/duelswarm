"""bloodhound_paths — the EXTERNAL judge of the credential-DAG.

Collect the range's AD over LDAP/SMB with bloodhound-python, then compute the shortest path to
Domain Admins / Tier 0. The credential graph is realistic iff an outside tool computes the same
SHAPE of attack path a real AD env yields: reachable, but only by chaining loot-then-reuse across
>=2-3 hops (never a one-step crown). Auditor only; output never fed to red.

Two layers, deliberately split so the invariant is testable without a live DC:
  * `shortest_path_to_da(graph, starts, da_node, min_hops)` — pure graph BFS over a normalized
    {nodes, edges:[(src,dst,type)]} graph. This holds the >=min_hops invariant and is what the
    offline selftest pins.
  * `from_bloodhound_json(out_dir)` — best-effort adapter from bloodhound-python's collected JSON
    to that normalized graph (MemberOf / AdminTo / HasSession / CanRDP / GenericAll edges). Run on
    the host against real collection output.
  * `collect_and_judge(...)` — run the real collector, adapt, judge.
"""
import glob
import json
import sys
from collections import deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from scripts.validation._common import verdict, unmeasured, run_tool, first_available  # noqa: E402

BLOODHOUND = ["bloodhound-python", "bloodhound-ce-python"]
# BH edges that represent a usable attacker traversal (loot-then-reuse / privilege).
TRAVERSAL_EDGES = {"MemberOf", "AdminTo", "HasSession", "CanRDP", "CanPSRemote",
                   "GenericAll", "GenericWrite", "WriteDacl", "Owns", "ForceChangePassword",
                   "AllowedToDelegate", "HasSIDHistory", "ExecuteDCOM"}


def shortest_path_to_da(graph, starts, da_node, min_hops=2):
    """BFS the normalized graph for the shortest path from any `starts` principal to `da_node`.
    Returns (path | None, all_shortest_lengths). A path of `k` edges = k loot/reuse hops."""
    nodes = {n.upper() for n in graph["nodes"]}
    adj = {}
    for src, dst, _etype in graph["edges"]:
        adj.setdefault(src.upper(), []).append(dst.upper())
    target = da_node.upper()
    best = None
    for s in starts:
        s = s.upper()
        if s not in nodes:
            continue
        # BFS
        q = deque([(s, [s])])
        seen = {s}
        while q:
            cur, path = q.popleft()
            if cur == target:
                if best is None or len(path) < len(best):
                    best = path
                break
            for nxt in adj.get(cur, []):
                if nxt not in seen:
                    seen.add(nxt)
                    q.append((nxt, path + [nxt]))
    return best, (len(best) - 1 if best else None)


def from_bloodhound_json(out_dir):
    """Best-effort normalize bloodhound-python JSON -> {nodes, edges}. Exercised on the host
    against real collection output; the pure BFS above is what the selftest pins."""
    nodes, edges = set(), []
    files = glob.glob(str(Path(out_dir) / "*.json"))
    for f in files:
        try:
            doc = json.loads(Path(f).read_text())
        except Exception:
            continue
        for obj in doc.get("data", []):
            props = obj.get("Properties", {}) or {}
            name = props.get("name") or props.get("Name")
            if not name:
                continue
            nodes.add(name)
            # group membership
            pgid = obj.get("PrimaryGroupSID")
            if pgid:
                edges.append((name, str(pgid), "MemberOf"))
            for m in obj.get("Members", []) or []:
                mn = (m.get("ObjectIdentifier") or m.get("name") or "")
                if mn:
                    nodes.add(mn)
                    edges.append((mn, name, "MemberOf"))
            # ACL / admin edges
            for ace in obj.get("Aces", []) or []:
                right = ace.get("RightName") or ace.get("Right")
                princ = ace.get("PrincipalSID") or ace.get("principal")
                if right in TRAVERSAL_EDGES and princ:
                    nodes.add(princ)
                    edges.append((princ, name, right))
            for la in obj.get("LocalAdmins", {}).get("Results", []) if isinstance(obj.get("LocalAdmins"), dict) else []:
                lan = la.get("ObjectIdentifier")
                if lan:
                    nodes.add(lan)
                    edges.append((lan, name, "AdminTo"))
    return {"nodes": sorted(nodes), "edges": edges}


def collect_and_judge(domain, dc_ip, username, password, out_dir,
                      da_node="DOMAIN ADMINS", foothold_principals=None, min_hops=2, timeout=240):
    b = first_available(BLOODHOUND)
    if not b:
        return unmeasured("bloodhound_paths", "bloodhound-python not installed")
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    argv = [b, "-d", domain, "-u", username, "-p", password, "-dc", dc_ip, "-ns", dc_ip,
            "-c", "All", "--zip"]
    r = run_tool(argv, timeout=timeout)
    graph = from_bloodhound_json(out_dir)
    if not graph["nodes"]:
        return verdict("bloodhound_paths", available=True, ok=False,
                       detail="collection produced no graph (collector failed or empty AD)",
                       evidence={"argv": argv, "rc": r["rc"], "err": r["err"][:300]})
    starts = foothold_principals or [n for n in graph["nodes"]]
    path, hops = shortest_path_to_da(graph, starts, da_node, min_hops=min_hops)
    ok = path is not None and hops is not None and hops >= min_hops
    detail = (f"shortest path to {da_node}: {hops} hops ({' -> '.join(path)})" if path
              else f"NO path to {da_node} — credential DAG does not reach Tier 0")
    return verdict("bloodhound_paths", available=True, ok=ok, detail=detail,
                   evidence={"argv": argv, "rc": r["rc"], "hops": hops, "path": path,
                             "nodes": len(graph["nodes"]), "edges": len(graph["edges"])})


def _selftest():
    # A credential DAG: wks -> svc_sql (roast) -> SRV01 (admin) -> DOMAIN ADMINS. The ONLY path
    # to DA is 3 hops; a direct wks->DA edge must NOT exist (no one-step crown).
    graph = {
        "nodes": ["WKS01", "SVC_SQL", "SRV01", "DOMAIN ADMINS", "DECOY"],
        "edges": [
            ("WKS01", "SVC_SQL", "GenericAll"),
            ("SVC_SQL", "SRV01", "AdminTo"),
            ("SRV01", "DOMAIN ADMINS", "MemberOf"),
            ("DECOY", "DECOY", "MemberOf"),
        ],
    }
    path, hops = shortest_path_to_da(graph, ["WKS01"], "DOMAIN ADMINS", min_hops=2)
    assert path == ["WKS01", "SVC_SQL", "SRV01", "DOMAIN ADMINS"], path
    assert hops == 3 and hops >= 2, hops

    # No path case (crown unreachable from a start with no edges) -> None.
    p2, h2 = shortest_path_to_da(graph, ["DECOY"], "DOMAIN ADMINS")
    assert p2 is None and h2 is None, (p2, h2)

    # A one-step crown (would FAIL the >=2-hop realism invariant) is detectable.
    flat = {"nodes": ["WKS01", "DOMAIN ADMINS"], "edges": [("WKS01", "DOMAIN ADMINS", "AdminTo")]}
    p3, h3 = shortest_path_to_da(flat, ["WKS01"], "DOMAIN ADMINS")
    assert h3 == 1 and h3 < 2, (p3, h3)   # ok would be False under min_hops=2

    # Adapter degrades (empty dir -> empty graph, no crash).
    import tempfile
    assert from_bloodhound_json(tempfile.mkdtemp()) == {"nodes": [], "edges": []}

    # Collector absent -> UNMEASURED (never a silent pass).
    if not first_available(BLOODHOUND):
        v = collect_and_judge("RANGE.LAB", "10.11.0.5", "u", "p", tempfile.mkdtemp())
        assert v["available"] is False and v["ok"] is None, v
    print("bloodhound_paths selftest: OK")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="bloodhound-python -> shortest path to Domain Admins")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--domain"); ap.add_argument("--dc-ip"); ap.add_argument("--user")
    ap.add_argument("--password"); ap.add_argument("--out", default="data/validation/bloodhound")
    ap.add_argument("--min-hops", type=int, default=2)
    a = ap.parse_args()
    if a.selftest or not (a.domain and a.dc_ip and a.user):
        _selftest()
    else:
        from scripts.validation._common import print_verdict
        import sys as _s
        v = collect_and_judge(a.domain, a.dc_ip, a.user, a.password or "", a.out, min_hops=a.min_hops)
        print_verdict(v)
        _s.exit(0 if v["available"] and v["ok"] else (2 if not v["available"] else 1))
