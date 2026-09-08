#!/bin/bash
#
#####################################################
#
#  Projekt: BSI-507
#  Netbox Installation
#  file: install.bash
#
#####################################################


echo "Installing starting..."


NETBOX_ENV_FILE="$(dirname "$0")/env/netbox.env"

if [ ! -f "$NETBOX_ENV_FILE" ]; then
  FILE="$NETBOX_ENV_FILE"
else
  echo "$NETBOX_ENV_FILE not found" >&2
  exit 1
fi


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

# Keep major & minor version in sync with NETBOX_DOCKER_VERSION in ../docker-ci/env/netbox.env
# Lookup the latest patch release at https://github.com/netbox-community/netbox-docker/releases

get_version
version="v.${maj}.${min}.${patch}"
echo "Use version ${version} of NetBox"
git clone -b ${version} https://github.com/netbox-community/netbox.git .

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

python3 manage.py runserver 0.0.0.0:8000



# ######################################################


get_version(){

  value=$(grep -E '^[[:space:]]*NETBOX_DOCKER_VERSION=' "$FILE" | head -n1 | cut -d'=' -f2- | tr -d '[:space:]' | tr -d '\r')
  nb=${value#v}; nb=${nb%%-*}      
  maj=${nb%%.*}                    
  min=${nb#*.}                     
  declare -g patch
  echo "Getting lastest patch state for $maj.$min"
  patch=$(
    curl -fsSL "https://api.github.com/repos/netbox-community/netbox/tags?per_page=100" |
      grep -oE "v${maj}\\.${min}\\.[0-9]+" |
      grep -oE '[0-9]+$' |
      sort -n |
      tail -n1
  ) || true

  if [[ -z "$patch" ]]; then
    patch=$(
      curl -fsSL "https://github.com/netbox-community/netbox/tags" |
        grep -oE "releases/tag/v${maj}\\.${min}\\.[0-9]+" |
        head -n1 |
        grep -oE '[0-9]+$'
    ) || true
  fi

  [[ -n "$patch" ]] || {
    echo "No tag v${maj}.${min}.* found" >&2
    return 1
  }
  return 0
}
