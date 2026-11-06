# V3 full-chain entry: the REAL vulnerable Apache Struts (CVE-2017-5638 / S2-045) PLUS an
# ssh client, so red's real OGNL RCE foothold can carry out a REAL credential pivot over
# ssh to the internal DB net (closing the DMZ->internal-pivot hop end-to-end). The Struts
# app is unchanged (still exploitable); we only add attacker-usable tooling. Base is Debian
# 8 jessie (archived), so apt is pinned to jessie/main with expiry/auth checks disabled —
# build-time only; the booted container runs offline on internal:true range nets.
#   - openssh-client: the real ssh pivot struts->db over the earned foothold (v3 full-chain).
#   - iproute2 + netcat-traditional: so the autonomous frontier's `recon_from` move can run
#     its own connect-scan (nc -z) and self-IP enumeration (ip -o -4 addr) FROM this foothold
#     when it is the range entry — the same scan primitives the alpine range-node ships with.
FROM piesecurity/apache-struts2-cve-2017-5638
RUN rm -f /etc/apt/sources.list.d/*.list \
 && printf 'deb [trusted=yes check-valid-until=no] http://archive.debian.org/debian/ jessie main\n' > /etc/apt/sources.list \
 && apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get install -y --no-install-recommends --allow-unauthenticated openssh-client iproute2 netcat-traditional \
 && which ssh nc ip
