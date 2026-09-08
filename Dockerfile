ARG NETBOX_DOCKER_VERSION=4.4.0-4.0.0  ## silence the warning of missing default value
FROM netboxcommunity/netbox:${NETBOX_DOCKER_VERSION}


COPY . /plugins
RUN /usr/local/bin/uv pip install  --editable  /plugins

COPY docker-ci/configuration/configuration.py /etc/netbox/config/configuration.py
COPY docker-ci/configuration/plugins.py /etc/netbox/config/plugins.py
