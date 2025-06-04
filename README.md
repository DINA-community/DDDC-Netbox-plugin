# Netbox Plugin DDDC

Even if there are tools in Malcolm and [Netbox itself](https://docs.netboxlabs.com/netbox-extensions/diode-overview/) getting data into Netbox, this data should be standardized. This is done by this plugin, which contains the source code for the BSI Project 507 TP2. The DDDC plugin can receive input data from various sources, supports the processing and approval of this data in order to build a standardized device database within Netbox.\\
The main features are further developed in the repository [String-Atlas](https://github.com/DINA-community/String-Atlas). This processes the data before it is placed in the Netbox framework. This ensures that the data is adapted to support IT security management tasks such as device management, vulnerability management and patch management.

In addition to the plugin code, this repository contains additional files for the community-driven [Docker image](https://github.com/netbox-community/netbox-docker) integrating the DDDC Plugin in development mode. This is primarily used for test purposes for the CI/CD pipeline and can be used for testing the plugin within an exemplary Netbox environment.

## Installation of the DDDC Plugin

As the DDDC plugin is a standard Netbox plugin, it can be installed according to the [Netbox documentation](https://docs.netbox.dev/en/stable/plugins/#installing-plugins). 
This plugin is compatible with Netbox version 4.2.7 and ensured by the docker file.

Additionally, this repository contains files from the community-driven Docker image to set up Netbox, along with all its dependencies, such as a PostgreSQL database. Please note: This is not an installation for a production environment, as it uses default passwords and API keys as specified in the project's files. Furthermore, this installation sets up Netbox in 'developer mode', which means that the user will receive detailed information in case of an exception. This is very useful for alpha and beta testing, which is why this installation option is described below:

## Installation via Docker for developing and testing purposes

### Prerequisites

This Dockerfile simply extends the [netbox-docker](https://github.com/netbox-community/netbox-docker) project with the custom DDDC-plugin. Therefore, the dependencies of the netbox-docker project also apply for this installation:

Recommendation: Install docker with the Compose v2 already integrated into the Docker CLI platform.

To check the version installed on your system run `docker --version` and `docker compose version`.

After the installation, Netbox is available at [http://127.0.0.1:8000](http://127.0.0.1:8000).
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

   ```bash
   git clone https://github.com/DINA-community/DDDC-Netbox-plugin.git
   cd DDDC-Netbox-plugin/
   docker compose build --no-cache
   docker compose up
   ```

2. Wait until `Initialization is done.` is printed. Afterwards the GUI can be accessed via [http://127.0.0.1:8000](http://127.0.0.1:8000).
3. Login as
   - BN: admin
   - PW: admin

After testing, the containers can be stopped by pressing `Ctrl+C` and restarted using `docker-compose up`.

### Notes regarding the installation of this plugin via the provided files

The installation will provide a warning message since the installation is using the default security token:

```text
⚠️ Warning: You have the old default admin token in your database. This token is widely known; please remove it.
```

In theory, you can add an alternative security token in the file netbox.env by adding the following line:

```python
SUPERUSER_API_TOKEN=<Token>
```

However, an important aspect of an installation in a production environment is the creation of users, tokens, and their permissions. This must be done for each Netbox installation separately and in accordance with the specific requirements in place.

### Testing

The unit tests of netbox can be executed via `./docker-ci/test.sh`.

## Help

This section contains links for familiarizing yourself with Django, Netbox, and plugins.

### General

- Installation of NetBox as a standalone, self-hosted application: <https://docs.netbox.dev/en/stable/installation/>
- Community driven Docker image for netbox: <https://github.com/netbox-community/netbox-docker>
- Using Netbox Plugins in Docker: <https://github.com/netbox-community/netbox-docker/wiki/Using-Netbox-Plugins>

### Development

- Official plugin development documentation of NetBox: <https://docs.netbox.dev/en/stable/plugins/development/>
- NetbBox plugin development Tutorial: <https://github.com/netbox-community/netbox-plugin-tutorial>
- Setting up a development environment with Docker for NetBox plugins: <https://github.com/netbox-community/netbox-docker/discussions/746>
- django-table2 Documentation used by the Plugin and Netbox: <https://django-tables2.readthedocs.io/en/latest/>
