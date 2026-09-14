#!/bin/bash
#
# Minimal integration test
#
# 1. Grabs the CSRF token
# 2. Logs in and checks the return
# 3. fetches one page

set -euo pipefail

base_url="${1:-http://localhost:8000}"
username="admin"  # Read that from docker-ci/env/netbox.env?
password="admin"

cookies=$(mktemp)

# On exit, remove the remporary directory
trap 'rm -f "$cookies"' EXIT

login_url="$base_url/login/"

# 1. Retrieve CSRF token and cookies
login_page=$(curl -sS -c "$cookies" "$login_url")
csrf_token=$(grep -o 'name="csrfmiddlewaretoken" value="[^"]*"' <<<"$login_page" | sed 's/.*value="//;s/"//')

if [ -z "$csrf_token" ]; then
  echo "ERROR: Could not find CSRF token on login page" >&2
  exit 1
fi

# 2. Login with credentials
login_response=$(curl -sS --fail \
  -b "$cookies" -c "$cookies" \
  --data-urlencode "csrfmiddlewaretoken=$csrf_token" \
  --data-urlencode "username=$username" \
  --data-urlencode "password=$password" \
  --data-urlencode "next=/" \
  "$login_url")

# If it fails, we get the login page again, so check the response body
if grep -q 'name="username"' <<<"$login_response"; then
  echo "ERROR: Login failed: still on login page after submitting credentials" >&2
  exit 1
fi

echo "Login OK"

# 3. Fetch a d3c plugin page
# can be extended to a list of pages
page_url="$base_url/plugins/d3c/findings/"
curl -sS --fail -o /dev/null -b "$cookies" "$page_url"

echo "GET $page_url OK"
echo "Integration test passed."
