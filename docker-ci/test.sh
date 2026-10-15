#!/bin/bash

# exit when a command exits with an exit code != 0
set -e


# The docker compose command to use
doco="docker compose --file $(dirname "$0")/docker-compose.test.yml --env-file $(dirname "$0")/../.env --project-name netbox_docker_test"

test_setup() {
  echo "🏗 Setup up test environment"
  $doco build --no-cache
  $doco up  --quiet-pull --wait --force-recreate --renew-anon-volumes --no-start
  $doco start postgres
  $doco start redis
  $doco start redis-cache
}

# docker-entrypoint.sh is the CMD, not ENTRYPOINT, so call it explicitly for the custom commands
netbox_run() {
  $doco run --rm netbox /opt/netbox/docker-entrypoint.sh "$@"
}

test_netbox_import_example_data() {
  echo "⏱ Importing d3c example data"
  netbox_run /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py d3c_example_data
}

test_netbox_unit_tests() {
  echo "⏱ Running d3c Unit Tests"
  # D3C's changes to DeviceType's behaviour make the dcim.tests.test_views.DeviceTypeTestCase fail, so we can only execute our own tests
  netbox_run /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py test d3c --noinput
}

test_cleanup() {
  echo "💣 Cleaning Up"
  $doco logs --no-color netbox
  $doco down --volumes
}

echo "🐳🐳🐳 Start testing"

# Make sure the cleanup script is executed
trap test_cleanup EXIT ERR
test_setup

test_netbox_import_example_data

test_netbox_unit_tests

echo "🐳🐳🐳 Done testing"
