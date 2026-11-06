# N1 — range node base: a real OpenSSH server + client on alpine, baked at BUILD time.
# The range's data-plane networks are internal:true (no internet), so packages cannot
# be installed at container boot — openssh must already be in the image. Built on the
# Docker host (which has egress) and referenced by the generated compose; the booted
# container then runs fully offline. This replaces the nc-listener stub on port 22 with
# a REAL sshd, so a credential pivot is a real key-authenticated SSH session (N1).
FROM alpine
RUN apk add --no-cache openssh
