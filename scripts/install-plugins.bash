#!/bin/bash
#
#####################################################
#
#  Projekt: BSI-507
#  Netbox Installation
#  file: install-plugins.bash
#
#####################################################
#
#  Fraunhofer IOSB
#  Fraunhoferstr. 1
#  D-76131 Karlsruhe
#
#####################################################

echo "Installing starting..."

git config --global user.name "Joerg Mustermann"

/usr/bin/cp -r /home/d3c/d3c /opt/netbox/
/usr/bin/rm -rf /opt/netbox/d3c/migrations/
/usr/bin/cp /home/d3c/configuration.py /opt/netbox/netbox/netbox/
/usr/bin/cp /home/d3c/pyproject.toml /opt/netbox/

cd /opt/netbox
source /opt/netbox/venv/bin/activate

pip install -e
#python3 netbox/manage.py makemigrations d3c --dry-run
python3 netbox/manage.py makemigrations d3c
python3 netbox/manage.py migrate

######################################################






