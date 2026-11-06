#!/bin/sh
set -e
# Start the real Sliver C2 server (multiplayer gRPC daemon); listeners + sessions persist here.
sliver-server daemon --lhost 0.0.0.0 --lport 31337 &
SRV=$!
# wait for the daemon + its CA to initialize
for i in $(seq 1 30); do
  sliver-server operator --name red --lhost 127.0.0.1 --lport 31337 --permissions all --save /root/op.cfg >/dev/null 2>&1 && break
  sleep 1
done
# bring up the HTTP C2 listener so real implants can beacon in
sliver-client --config /root/op.cfg --rc /start_listener.rc >/root/listener.log 2>&1 || true
echo "SLIVER_C2_READY"
wait $SRV
