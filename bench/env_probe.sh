#!/usr/bin/env bash
# Environment probe for the Phase 8 speed track (WSL quoting is unreliable,
# so run diagnostics from this file instead of inline command lines).
set -u
echo "== tools =="
for t in nmap masscan rustscan naabu zmap perf hyperfine python3; do
  if command -v "$t" >/dev/null 2>&1; then
    echo "$t: $(command -v "$t")"
  else
    echo "$t: MISSING"
  fi
done
echo "== cpu/io =="
echo "nproc: $(nproc)"
echo "local port range: $(cat /proc/sys/net/ipv4/ip_local_port_range)"
echo "somaxconn: $(cat /proc/sys/net/core/somaxconn)"
echo "== file limits =="
ulimit -n
echo "== rayscan release =="
if [ -x /tmp/rayscan-target/release/rayscan ]; then
  /tmp/rayscan-target/release/rayscan --version
fi
