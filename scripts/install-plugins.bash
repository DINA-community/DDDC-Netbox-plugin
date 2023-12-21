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

git config --global user.name "Joerg Kippe"

/usr/bin/cp -r /home/d3c/plugins/d3c /opt/netbox/
/usr/bin/rm -rf /opt/netbox/d3c/migrations/
/usr/bin/cp /home/d3c/plugins/configuration.py /opt/netbox/netbox/netbox/
/usr/bin/cp /home/d3c/plugins/setup.py /opt/netbox/

cd /opt/netbox
source /opt/netbox/venv/bin/activate

python3 setup.py develop
#python3 netbox/manage.py makemigrations d3c --dry-run
python3 netbox/manage.py makemigrations d3c
python3 netbox/manage.py migrate

######################################################






