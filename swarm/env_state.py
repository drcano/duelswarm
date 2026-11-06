"""Environment-state service (Brick 1, DUELSWARM_LIQUID_SPEC §5.1).

Red's belief about the network, event-sourced from the hash-chained log — the
Incalmo `parse_events` pattern (`handle_HostsDiscovered / ServicesDiscoveredOnHost /
CredentialFound`). The load-bearing invariant for objective-blindness: a host, a
credential, or the crown appears in belief **iff** a prior discovery event
introduced it. Red never reads the range ground truth; it only knows what it has
discovered. The crown's identity can therefore enter belief ONLY through a
`discovery` event with `kind="crown_data"` — never an injected objective.

Discovery events are emitted by the range/responder (actor != red), action
`discovery`, with `data.kind` one of:
  * "hosts"        : {"from": <foothold>, "hosts": [{"name","ips","services"}]}
  * "services"     : {"host": <name>, "services": {port: service}}
  * "creds"        : {"host": <name>, "creds": [{"username","host_ip",...}]}
  * "crown_data"   : {"host": <name>}   # enumeration revealed the crown jewels here
  * "ssh_keys"     : {"host": <name>, "username": <u>, "works_on": [{"host","username"}]}
                     # M2: Incalmo-shaped credential pivots from MHBench User.ssh_keys —
                     # one entry per usable (host,user) the discovered key logs into.
  * "privesc_vuln" : {"host": <name>, "username": <u>, "to_user": <root>, "vuln": <name>}
                     # M2: privesc opportunity discovered on a held foothold (e.g.
                     # SudoBaron / WriteablePasswd); feeds the privesc frontier move.
"""


class EnvState:
    def __init__(self):
        self.hosts = {}      # name -> {ips, services, has_crown_data, infected, discovered_via,
                             #          users:{u: {root:bool}}, ssh_keys_from:[(src_host, src_user, dst_host, dst_user)],
                             #          privesc:[{"user","to_user","vuln"}]}
        self.creds = []      # [{username, host_ip, ...}]

    def _host(self, name):
        return self.hosts.setdefault(name, {
            "ips": [], "services": {}, "has_crown_data": False,
            "infected": False, "discovered_via": None,
            "users": {}, "ssh_keys_from": [], "privesc": []})

    def handle_HostsDiscovered(self, data, seq):
        frm = data.get("from")
        for h in data.get("hosts", []):
            rec = self._host(h["name"])
            if rec["discovered_via"] is None:
                rec["discovered_via"] = {"seq": seq, "from": frm}
            for ip in h.get("ips", []):
                if ip not in rec["ips"]:
                    rec["ips"].append(ip)
            rec["services"].update({int(p): s for p, s in (h.get("services") or {}).items()})

    def handle_ServicesDiscoveredOnHost(self, data, seq):
        rec = self._host(data["host"])
        if rec["discovered_via"] is None:
            rec["discovered_via"] = {"seq": seq}
        rec["services"].update({int(p): s for p, s in (data.get("services") or {}).items()})

    def handle_CredentialFound(self, data, seq):
        for c in data.get("creds", []):
            if c not in self.creds:
                self.creds.append(c)

    def handle_CrownDataFound(self, data, seq):
        rec = self._host(data["host"])
        rec["has_crown_data"] = True
        if rec["discovered_via"] is None:
            rec["discovered_via"] = {"seq": seq}

    def handle_SSHKeysFound(self, data, seq):
        """M2 — credential-pivot discovery (Incalmo `SSHCredential.works_on`).

        A key discovered on `host`/`username` logs into each `works_on` entry,
        creating a credential-driven lateral move for the frontier. Each dst
        host also enters belief as discovered (an edge the key reveals)."""
        src_host, src_user = data["host"], data.get("username", "")
        src_rec = self._host(src_host)
        src_rec["users"].setdefault(src_user, {"root": False})
        for w in data.get("works_on") or []:
            dst_host, dst_user = w["host"], w.get("username", "")
            # the key reveals the destination host as discovered (edge-of-reach).
            drec = self._host(dst_host)
            if drec["discovered_via"] is None:
                drec["discovered_via"] = {"seq": seq, "from": src_host, "via": "ssh_key"}
            drec["users"].setdefault(dst_user, {"root": dst_user == "root"})
            edge = (src_host, src_user, dst_host, dst_user)
            if edge not in src_rec["ssh_keys_from"]:
                src_rec["ssh_keys_from"].append(edge)

    def handle_PrivescVulnFound(self, data, seq):
        """M2 — privesc opportunity on a held host (SudoBaron / WriteablePasswd)."""
        rec = self._host(data["host"])
        rec["users"].setdefault(data.get("username", ""), {"root": False})
        entry = {"user": data.get("username", ""),
                 "to_user": data.get("to_user", "root"),
                 "vuln": data.get("vuln", "privesc")}
        if entry not in rec["privesc"]:
            rec["privesc"].append(entry)

    _DISPATCH = {
        "hosts": handle_HostsDiscovered,
        "services": handle_ServicesDiscoveredOnHost,
        "creds": handle_CredentialFound,
        "crown_data": handle_CrownDataFound,
        "ssh_keys": handle_SSHKeysFound,
        "privesc_vuln": handle_PrivescVulnFound,
    }

    def apply(self, event):
        action = event.get("action")
        data = event.get("data") or {}
        if action == "discovery":
            fn = self._DISPATCH.get(data.get("kind"))
            if fn:
                fn(self, data, event.get("seq"))
        elif action == "state.mutate" and data.get("state") in ("foothold", "lateral"):
            # infection enters belief only via a Brick-0 confirmed foothold/lateral
            # (swarm.spine.mutate), never a self-report — same observable discipline.
            self._host(data["dst"])["infected"] = True
            u = data.get("as_user")
            if u:
                self._host(data["dst"])["users"].setdefault(u, {"root": u == "root"})
        elif action == "state.mutate" and data.get("state") == "privesc":
            # M2 — a confirmed privesc elevates the user on the held host to root.
            rec = self._host(data["dst"])
            rec["users"][data.get("to_user", "root")] = {"root": True}

    def mark_infected(self, name):
        self._host(name)["infected"] = True

    def known_hosts(self):
        return set(self.hosts)

    def crown_candidates(self):
        """Hosts red has DISCOVERED to carry crown data (empty until discovery)."""
        return [n for n, r in self.hosts.items() if r["has_crown_data"]]

    @classmethod
    def from_log(cls, entries):
        st = cls()
        for e in entries:
            st.apply(e)
        return st


if __name__ == "__main__":  # self-check: belief grows ONLY from discovery events
    E = [
        {"seq": 0, "actor": "system", "action": "scope", "data": {"in_scope": ["struts"]}},
        {"seq": 1, "actor": "red", "action": "gate.allow", "data": {"tool": "recon", "target": "struts"}},
        {"seq": 2, "actor": "range", "action": "discovery",
         "data": {"kind": "hosts", "from": "struts",
                  "hosts": [{"name": "struts", "ips": ["10.10.0.2"], "services": {"8080": "http"}}]}},
    ]
    st = EnvState.from_log(E)
    assert st.known_hosts() == {"struts"}, st.known_hosts()
    assert st.hosts["struts"]["services"] == {8080: "http"}
    # the crown is NOT known yet — no crown_data event
    assert st.crown_candidates() == [], "crown must not be known before discovery"

    # discover a neighbor + its crown data
    st.apply({"seq": 3, "actor": "range", "action": "discovery",
              "data": {"kind": "hosts", "from": "struts",
                       "hosts": [{"name": "db", "ips": ["10.11.0.3"], "services": {"5432": "postgres"}}]}})
    assert "db" in st.known_hosts() and not st.hosts["db"]["has_crown_data"]
    st.apply({"seq": 4, "actor": "range", "action": "discovery",
              "data": {"kind": "crown_data", "host": "db"}})
    assert st.crown_candidates() == ["db"], "crown enters belief only via crown_data discovery"

    # creds only from a CredentialFound event
    assert st.creds == []
    st.apply({"seq": 5, "actor": "range", "action": "discovery",
              "data": {"kind": "creds", "host": "struts",
                       "creds": [{"username": "tomcat", "host_ip": "10.11.0.3"}]}})
    assert len(st.creds) == 1

    # a non-discovery event (e.g. a red reasoning line naming a host) does NOT
    # leak into belief
    before = EnvState.from_log(E).known_hosts()
    st2 = EnvState.from_log(E + [{"seq": 9, "actor": "red", "action": "reasoning",
                                  "data": {"text": "the crown is probably on db"}}])
    assert st2.known_hosts() == before, "belief must not grow from red's narration"

    # ── M2: credential-pivot + privesc discovery kinds. ──
    # ssh_keys discovery: reveals the dst host AND registers the pivot edge.
    st.apply({"seq": 6, "actor": "range", "action": "discovery",
              "data": {"kind": "ssh_keys", "host": "struts", "username": "deploy",
                       "works_on": [{"host": "db2", "username": "dbadmin"}]}})
    assert "db2" in st.known_hosts(), "ssh-key dst must enter belief"
    assert st.hosts["db2"]["discovered_via"]["via"] == "ssh_key", st.hosts["db2"]
    assert ("struts", "deploy", "db2", "dbadmin") in st.hosts["struts"]["ssh_keys_from"]
    # privesc_vuln: records the opportunity; does NOT elevate on its own.
    st.apply({"seq": 7, "actor": "range", "action": "discovery",
              "data": {"kind": "privesc_vuln", "host": "struts", "username": "www-data",
                       "to_user": "root", "vuln": "SudoBaron"}})
    assert {"user": "www-data", "to_user": "root", "vuln": "SudoBaron"} in st.hosts["struts"]["privesc"]
    assert not st.hosts["struts"]["users"].get("root", {}).get("root")
    # a confirmed privesc state.mutate elevates: belief now records root on struts.
    st.apply({"seq": 8, "actor": "red", "action": "state.mutate",
              "data": {"state": "privesc", "dst": "struts", "to_user": "root"}})
    assert st.hosts["struts"]["users"]["root"]["root"] is True, "privesc must elevate user"

    print("env_state ok (belief event-sourced; nothing known before it is discovered; "
          "M2: ssh_keys + privesc_vuln discovery kinds + privesc state.mutate elevates)")
