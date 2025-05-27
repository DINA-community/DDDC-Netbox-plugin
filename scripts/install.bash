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

echo "Installing starting..."

git config user.email "root@assetmanager.bsi.corp"

apt-get update

# 1. PostgreSQL

cd /home/DDDC-Netbox-plugin
apt install -y postgresql
systemctl start postgresql
systemctl enable postgresql

cp /home/DDDC-Netbox-plugin/scripts/pg_hba.conf /etc/postgresql/14/main/pg_hba.conf

sudo -i -u postgres psql -f /home/DDDC-Netbox-plugin/scripts/initdb.sql
 
# 2. Redis

apt install -y redis-server
# redis-server -v
# redis-cli ping

# 3. NetBox

apt install -y python3 python3-pip python3-venv python3-dev build-essential libxml2-dev libxslt1-dev libffi-dev libpq-dev libssl-dev zlib1g-dev

# python3 -V

mkdir -p /opt/netbox/
cd /opt/netbox/

git clone -b v4.3.1 https://github.com/netbox-community/netbox.git .

adduser --system --group netbox
chown --recursive netbox /opt/netbox/netbox/media/

#python3 /opt/netbox/netbox/generate_secret_key.py > /home/netbox/secret_key

# cd /opt/netbox/netbox/netbox/
cp /home/DDDC-Netbox-plugin/scripts/configuration.py /opt/netbox/netbox/netbox/configuration.py

# #edit configuration.py

# python3 ../generate_secret_key.py

/opt/netbox/upgrade.sh

source /opt/netbox/venv/bin/activate

cd /opt/netbox/netbox
python3 manage.py createsuperuser

ln -s /opt/netbox/contrib/netbox-housekeeping.sh /etc/cron.daily/netbox-housekeeping

python3 manage.py runserver 0.0.0.0:8000 --insecure



# ######################################################



