#!/usr/bin/env sh
set -eu

echo "== OS =="
uname -a

echo "== CPU =="
nproc || true

echo "== Memory =="
free -h || true

echo "== Disk =="
df -h . || true

echo "== Docker =="
docker --version || true
docker compose version || true

echo "== Ports =="
ss -ltn || true
