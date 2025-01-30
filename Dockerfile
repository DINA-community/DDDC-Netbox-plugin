FROM netboxcommunity/netbox:latest


COPY ./plugins /plugins
RUN /opt/netbox/venv/bin/pip install  --editable  /plugins

COPY docker-ci/configuration/configuration.py /etc/netbox/config/configuration.py
COPY docker-ci/configuration/plugins.py /etc/netbox/config/plugins.py
