# Netbox versioning

---

[Overview](index.md) | [Contribution](contribute.md) | [Troubleshoot](troubleshoot.md) | [Tutorial](tutorial.md)

---

[Netbox](https://github.com/netbox-community/netbox/) and [netbox-docker](https://github.com/netbox-community/netbox-docker/) have differing version schemes

The git tags of netbox-docker and the docker image tags have the following format:

```text
v<netbox-major.minor>-<netbox-docker-version>
```

where

- `<netbox-major.minor>` is the major and minor version, e.g. `4.5`
- `<netbox-docker-version>` is the major, minor and patch version, e.g. `3.4.0`.

Examples:

- `v4.4-3.4.2`
- `v4.3-3.3.0`

## Changing the Netbox version

When bumping, the versions needs to be adapted in:

- `.env` (full string as explained above)
- `README.md`: netbox version and netbox-docker version in [Set the proper netbox docker version](../README.md#set-the-proper-netbox-docker-version) and [Installation of the DDDC Plugin](../README.md#installation-of-the-dddc-plugin)
- `d3c/__init__.py` (Netbox major and minor version)
