#!/bin/bash
#
#####################################################
#
#  Projekt: BSI-507
#  Netbox Installation
#  file: install.bash
#
#####################################################
#
#  Fraunhofer IOSB
#  Fraunhoferstr. 1
#  D-76131 Karlsruhe
#
#####################################################

source /opt/netbox/venv/bin/activate

python3 /opt/netbox/netbox/manage.py rqworker high default low &

python3 /opt/netbox/netbox/manage.py runserver 0.0.0.0:8000 --insecure &



# ######################################################



