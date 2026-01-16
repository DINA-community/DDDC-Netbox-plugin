# Troubleshoot

Not all problems are posted in issues. Therefore, this section lists some problems that may occur.

## Docker Compose Up

### dddc-netbox-plugin-netbox-1

If `Container dddc-netbox-plugin-netbox-1` is shown as an Error after overstepping the default time for running healthy. It is declared as unhealthy. A solution might be to stop the container and restart.

```bash
$docker compose stop
Container ... Stopped
$docker compose up
```

### netbox-worker and netbox-housekeeping

When the DDDC-Plugin is not up to date with the netbox version, breaking changes might cause problem even if the building process completes with no errors. In this case, prune the containers, images and volumes from the build and adjust `docker-compose.override.yml` to 

```bash
services:
  netbox:
    image: netbox:$Version
    pull_policy: never
    ports:
      - 8000:8080
    build:
      context: .
      dockerfile: Dockerfile-Plugins
  netbox-worker:
    image: netbox:$Version
    pull_policy: never
  netbox-housekeeping:
    image: netbox:$Version
    pull_policy: never
```

where `$Version` is the netbox version for the stabile DDDC-Plugin version like `v4.3-3.3.0`.
