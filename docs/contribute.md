# Contribution

---

[Overview](index.md) | [Contribution](contribute.md) | [Troubleshoot](troubleshoot.md) | [Tutorial](tutorial.md)

---

Requirements, tests and further information will be listed here...

## Local Development

The plugin directory is bind-mounted into the containers `netbox` and `netbox-worker` and installed in editable mode.
Changes to the plugin source code are picked up by the container without rebuilding the Docker image.

After making changes to the backend code of the NetBox module, either restart the affected containers:

```bash
docker compose restart netbox netbox-worker
```

Or, for faster feedback, you can reload only the NetBox application:

```bash
./dev/netbox-reload-plugins.sh
```

However, this only covers the `netbox` service itself, not `netbox-worker`.

Changes to frontend code (HTML, JS, CSSS) don't need a restart and only a reload in the browser.
