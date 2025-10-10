# Troubleshoot

Not all problems are posted in issues. Therefore, this section lists some problems that may occur.

## Docker Compose Up

If `Container dddc-netbox-plugin-netbox-1` is shown as an Error after overstepping the default time for running healthy. It is declared as unhealthy. A solution might be to stop the container and restart.

```bash
$docker compose stop
Container ... Stopped
$docker compose up
```
