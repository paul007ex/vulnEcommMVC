#!/usr/bin/env bash
# File: tests.sh
# Project: VulnerableECommerceMVC Lab
# Purpose: Exercise /, /insecure (HTTP) and /secure, /securelogin (HTTPS) endpoints
# Usage: chmod +x tests.sh && ./tests.sh

set -e

HOST_HTTP="http://localhost:8080"
HOST_HTTPS="https://localhost:8443"

# helper to produce Base64-encoded Basic header
basic_auth() {
  echo -n "$1:$2" | base64
}

echo
echo "=== 1) Insecure endpoint tests (HTTP) ==="
echo

echo "-- 1.1 No credentials (should 401) --"
curl -v "$HOST_HTTP/" || true

echo "-- 1.2 Alias no credentials (should 401) --"
curl -v "$HOST_HTTP/insecure" || true

echo "-- 1.3 Valid creds (john/password) --"
curl -v \
  -H "Authorization: Basic $(basic_auth john password)" \
  "$HOST_HTTP/"

echo "-- 1.4 Valid creds alias (admin/password) --"
curl -v \
  -H "Authorization: Basic $(basic_auth admin password)" \
  "$HOST_HTTP/insecure"

echo "-- 1.5 Invalid creds (jane/wrongpass) --"
curl -v \
  -H "Authorization: Basic $(basic_auth jane wrongpass)" \
  "$HOST_HTTP/" || true

echo
echo "=== 2) Insecure attack simulations ==="
echo

echo "-- 2.1 SQL injection in username --"
curl -v \
  -H "Authorization: Basic $(basic_auth \"admin';--\" password)" \
  "$HOST_HTTP/insecure" || true

echo "-- 2.2 Brute-force simulation --"
for user in admin john jane; do
  for pass in pass1 pass2 password; do
    status=$(curl -s -o /dev/null -w "%{http_code}" \
      -H "Authorization: Basic $(basic_auth $user $pass)" \
      "$HOST_HTTP/")
    echo "  [$status] $user:$pass"
  done
done

echo
echo "=== 3) Secure endpoint tests (HTTPS) ==="
echo "(Skipping cert check with -k)"
echo

echo "-- 3.1 No credentials (should 401) --"
curl -kv "$HOST_HTTPS/secure" || true

echo "-- 3.2 Alias no credentials (should 401) --"
curl -kv "$HOST_HTTPS/securelogin" || true

echo "-- 3.3 Valid creds (jane/password) --"
curl -kv \
  -H "Authorization: Basic $(basic_auth jane password)" \
  "$HOST_HTTPS/secure"

echo "-- 3.4 Valid creds alias (admin/password) --"
curl -kv \
  -H "Authorization: Basic $(basic_auth admin password)" \
  "$HOST_HTTPS/securelogin"

echo "-- 3.5 Invalid creds (john/wrongpass) --"
curl -kv \
  -H "Authorization: Basic $(basic_auth john wrongpass)" \
  "$HOST_HTTPS/secure" || true

echo
echo "=== 4) Secure attack simulation ==="
echo

echo "-- 4.1 SQL injection attempt in username --"
curl -kv \
  -H "Authorization: Basic $(basic_auth \"admin';--\" password)" \
  "$HOST_HTTPS/secure" || true

echo
echo "All tests executed."
