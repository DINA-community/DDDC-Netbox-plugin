#!/usr/bin/bash
# Reloads the NetBox application, so a full container restart is not needed.
# Edits under d3c/ take effect immediately.
#
# Service `netbox-worker` is unaffected.
#
# Granian gracefully respawns its workers on SIGHUP.
# The `tini --` entrypoint forwards all signals to Granian.
set -euo pipefail

cd "$(dirname -- "${BASH_SOURCE[0]}")"

docker compose exec netbox kill -HUP 1
echo "Sent SIGHUP to NetBox (Granian) to reload all workers."
