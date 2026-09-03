FROM netboxcommunity/netbox:v4.4-3.4.2


COPY . /plugins
RUN /usr/local/bin/uv pip install  --editable  /plugins

COPY docker-ci/configuration/configuration.py /etc/netbox/config/configuration.py
COPY docker-ci/configuration/plugins.py /etc/netbox/config/plugins.py
