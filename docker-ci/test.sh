#!/bin/bash

# exit when a command exits with an exit code != 0
set -e


# The docker compose command to use
doco="docker compose --file $(dirname "$0")/docker-compose.test.yml --file $(dirname "$0")/docker-compose.test.override.yml --project-name netbox_docker_test"

test_setup() {
  echo "🏗 Setup up test environment"
  $doco build --no-cache
  $doco up  --quiet-pull --wait --force-recreate --renew-anon-volumes --no-start
  $doco start postgres
  $doco start redis
  $doco start redis-cache
}

test_netbox_unit_tests() {
  echo "⏱ Running NetBox Unit Tests"
  $doco run --rm netbox /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py test # dcim.tests.test_api.PlatformTest
}

test_cleanup() {
  echo "💣 Cleaning Up"
  $doco logs --no-color
  $doco down --volumes
}

echo "🐳🐳🐳 Start testing"

# Make sure the cleanup script is executed
trap test_cleanup EXIT ERR
test_setup

test_netbox_unit_tests

echo "🐳🐳🐳 Done testing"
