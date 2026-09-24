# NetBox Plugin D3C

Even if there are tools in Malcolm and [NetBox itself](https://docs.netboxlabs.com/netbox-extensions/diode-overview/) getting data into NetBox, this data should be standardized. This is done by this plugin, which contains the source code for the BSI Project 507 TP2. The D3C ("Device Detection and Device Characterization") plugin can receive input data from various sources, supports the processing and approval of this data in order to build a standardized device database within NetBox.\\
The main features are further developed in the repository [String-Atlas](https://github.com/DINA-community/String-Atlas). This processes the data before it is placed in the NetBox framework. This ensures that the data is adapted to support IT security management tasks such as device management, vulnerability management and patch management.

In addition to the plugin code, this repository contains additional files for the community-driven [Docker image](https://github.com/netbox-community/netbox-docker) integrating the D3C Plugin in development mode. This is primarily used for test purposes for the CI/CD pipeline and can be used for testing the plugin within an exemplary NetBox environment.

## Installation of the D3C Plugin

As the D3C plugin is a standard NetBox plugin, it can be installed according to the [NetBox documentation](https://docs.netbox.dev/en/stable/plugins/#installing-plugins).
This plugin is compatible with NetBox version 4.6 and ensured by the docker file.

Additionally, this repository contains files from the community-driven Docker image to set up NetBox, along with all its dependencies, such as a PostgreSQL database. Please note: This is not an installation for a production environment, as it uses default passwords and API keys as specified in the project's files. Furthermore, this installation sets up NetBox in 'developer mode', which means that the user will receive detailed information in case of an exception. This is very useful for alpha and beta testing, which is why this installation option is described below:

## Adding the plugin to an existing netbox-docker installation

### Set the proper netbox docker version

D3C is only compatible with NetBox 4.6 and therefore with netbox-docker 5.0.2.
The exact tag to use is the second part of `NETBOX_DOCKER_VERSION` in `.env`.
For a new install, clone from that tag:

   ```bash
   git clone -b 5.0.2 https://github.com/netbox-community/netbox-docker.git
   ```

For existing installations, switch to that tag before continuing:

   ```bash
   git checkout 5.0.2
   ```

### Add plugin

The Plugin can be added to any existing or new setup of netbox-docker by following their [plugin instructions](https://github.com/netbox-community/netbox-docker/wiki/Using-Netbox-Plugins).

1. Create the file `plugin_requirements.txt` with the following content:

   ```bash
   git+https://github.com/DINA-community/D3C-Netbox-plugin.git
   ```

2. Create the file `Dockerfile-Plugins` with the content from the [netbox-docker documentation](https://github.com/netbox-community/netbox-docker/wiki/Using-Netbox-Plugins#dockerfile-plugins).
   Add this snippet before the line `RUN /usr/local/bin/uv pip`:

   ```bash
   RUN apt-get update && DEBIAN_FRONTEND="noninteractive" apt install -y git
   ```

   Also, replace

   ```bash
   FROM netboxcommunity/netbox:latest
   ```

   with

   ```bash
   FROM netboxcommunity/netbox:$NETBOX_DOCKER_VERSION
   ```

   using the value of `NETBOX_DOCKER_VERSION` in `.env`.

3. Create the file `docker-compose.override.yml` with the content from the [netbox-docker documentation](https://github.com/netbox-community/netbox-docker/wiki/Using-Netbox-Plugins#user-content-docker-composeoverrideyml).

   You can also create a superuser by adding these lines with meaningful values. Alternatively, create the superuser in step 6.

   ```yaml
         environment:
            SKIP_SUPERUSER: "false"
            #SUPERUSER_API_TOKEN: ""
            SUPERUSER_EMAIL: ""
            SUPERUSER_NAME: ""
            SUPERUSER_PASSWORD: ""
   ```

   Also, change the image versions

   ```yaml
      image: netbox:$NETBOX_DOCKER_VERSION
   ```

   for all services using the version used in steps above

4. Add this to `configuration/plugins.py`:

   ```python
   PLUGINS = ["d3c"]
   ```

   You can also add a section `PLUGINS_CONFIG` for d3c here.

5. Build and run it (see [Troubleshoot](./troubleshoot.md)):

   ```bash
   docker compose build --no-cache
   docker compose up -d
   ```

6. Access your local netbox by [http://127.0.0.1:8000](http://127.0.0.1:8000). To create an admin user, run this command:

   ```bash
   docker compose exec netbox /opt/netbox/netbox/manage.py createsuperuser
   ```

## Installation via Docker for developing and testing purposes

### Prerequisites

This Dockerfile simply extends the [netbox-docker](https://github.com/netbox-community/netbox-docker) project with the custom D3C-plugin. Therefore, the dependencies of the netbox-docker project also apply for this installation:

Recommendation: Install docker with the Compose v2 already integrated into the Docker CLI platform.

To check the version installed on your system run `docker --version` and `docker compose version`.

After the installation, NetBox is available at [http://127.0.0.1:8000](http://127.0.0.1:8000).
Therefore, for simplicity, a web browser should be available on the installed system.

### Installation for developing and testing purposes

1. Execute the following commands for [ubuntu](https://docs.docker.com/engine/install/ubuntu/):

   ```bash
   # Add official GPG key from docker
   apt update
   apt install apt-transport-https ca-certificates curl
   echo "deb [signed-by=/etc/apt/trusted.gpg.d/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list
   curl -fsSL "https://download.docker.com/linux/ubuntu/gpg" | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/docker.gpg > /dev/null
   apt-cache policy docker-ce
   apt-get install docker-ce
   ```

2. Build and run the plugin (see [Troubleshoot](./troubleshoot.md)):

   ```bash
   git clone https://github.com/DINA-community/D3C-Netbox-plugin.git
   cd D3C-Netbox-plugin/
   docker compose build --no-cache
   docker compose up
   ```

3. Access your local netbox by [http://127.0.0.1:8000](http://127.0.0.1:8000). To create an admin user, run this command:

   ```bash
   docker compose exec netbox /opt/netbox/netbox/manage.py createsuperuser
   ```

After testing, the containers can be stopped by pressing `Ctrl+C` and restarted using `docker-compose up`.

#### Debug mode

To enable the netbox debug mode, to get long and detailed tracebacks, add this to `docker-compose.yml` in the section `netbox`:

```yaml
    environment:
      - DEBUG=True
```

### Default accounts and API tokens

A default admin account (`admin`/`admin`) is created automatically via the `SUPERUSER_NAME`/`SUPERUSER_EMAIL`/`SUPERUSER_PASSWORD` variables in `docker-ci/env/netbox.env`.
As with the other default passwords and API keys in this repo's files, this is not suitable for a production environment.

To create an API token set these variables

- `SUPERUSER_API_TOKEN` (40 characters)
- `SUPERUSER_API_KEY` (12 characters)
- `API_TOKEN_PEPPER_1` (at least 50 characters)
in `docker-ci/env/netbox.env`.
Use the resulting token as `Authorization: Bearer nbt_<Key>.<Token>`.

The admin account and the API token are only created once, when the `admin` user does not yet exist.

However, an important aspect of an installation in a production environment is the creation of users, tokens, and their permissions. This must be done for each NetBox installation separately and in accordance with the specific requirements in place.

### Testing

The project includes Unit tests under `d3c/tests/`.

To run the tests, use:

- `make tests` which starts the stack and runs the tests
- `./docker-ci/test.sh` does the same in a separate docker stack
- `docker compose exec netbox /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py test d3c.tests.test_utils.ValidateUriTestCase` to run the specific test `ValidateUriTestCase` in test_utils.py in a running stack

NetBox's own `dcim.tests.test_views.DeviceTypeTestCase` are also used, because D3C overrides NetBox's built-in DeviceType views.

## Help

You can find additionally information under docs/

- [Contribution](docs/contribute.md)
- [Troubleshoot](docs/troubleshoot.md)
- [Tutorial](docs/tutorial.md)
