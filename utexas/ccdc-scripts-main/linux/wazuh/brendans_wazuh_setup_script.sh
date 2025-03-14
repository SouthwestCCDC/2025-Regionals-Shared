#!/bin/bash

# --- Get passwords
apt-get install pwgen
WAZ_IDX_PASS=$(pwgen -s -c -n 15 1)
WAZ_IDX_PASS+='a*'
WAZ_API_PASS=$(pwgen -s -c -n 15 1)
WAZ_API_PASS+='a*'
WAZ_DASH_PASS=$(pwgen -s -c -n 15 1)
WAZ_DASH_PASS+='a*'

# --- Increase max_map_count per wazuh docs
sysctl -w vm.max_map_count=262144

# --- Install docker
# Add Docker's official GPG key:
sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo \
	"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
	$(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
	sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update

sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin git

# --- Install wazuh
git clone https://github.com/wazuh/wazuh-docker.git -b v4.7.3
cd ./wazuh-docker/single-node

# This is ugly because I can't figure out how to escape strings easily
sed -i "s/password: \".*\(.*\)/password: \"$WAZ_API_PASS\"/gm" config/wazuh_dashboard/wazuh.yml

SED_SEARCH="s/API_PASSWORD=\(.*\)/API_PASSWORD="
SED_SEARCH+=$WAZ_API_PASS
SED_SEARCH+="/gm"
sed -i $SED_SEARCH docker-compose.yml

SED_SEARCH="s/INDEXER_PASSWORD=\(.*\)/INDEXER_PASSWORD="
SED_SEARCH+=$WAZ_IDX_PASS
SED_SEARCH+="/gm"
sed -i $SED_SEARCH docker-compose.yml

SED_SEARCH="s/DASHBOARD_PASSWORD=\(.*\)/DASHBOARD_PASSWORD="
SED_SEARCH+=$WAZ_DASH_PASS
SED_SEARCH+="/gm"
sed -i $SED_SEARCH docker-compose.yml

docker compose -f generate-indexer-certs.yml run --rm generator

WAZ_IDX_HASH=$(docker run --rm -ti wazuh/wazuh-indexer:4.7.3 bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p $WAZ_IDX_PASS | tail -1 | tr -d '\r')
WAZ_DASH_HASH=$(docker run --rm -ti wazuh/wazuh-indexer:4.7.3 bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p $WAZ_DASH_PASS | tail -1 | tr -d '\r')

echo "_meta:
    type: \"internalusers\"
    config_version: 2

admin:
    hash: \"$WAZ_IDX_HASH\"
    reserved: true
    backend_roles:
    - \"admin\"
    description: \"Admin user\"

kibanaserver:
    hash: \"$WAZ_DASH_HASH\"
    reserved: true
    description: \"kibanaserver user\"
" > config/wazuh_indexer/internal_users.yml

sed -i 's|<logall_json>no</logall_json>|<logall_json>yes</logall_json>|' config/wazuh_cluster/wazuh_manager.conf

docker compose up -d

sleep 30

docker exec single-node-wazuh.manager-1 /bin/bash -c "sed -i \"s/ enabled: false/ enabled: true/\" /etc/filebeat/filebeat.yml"
docker exec single-node-wazuh.indexer-1 /bin/bash -c "
        export JAVA_HOME=/usr/share/wazuh-indexer/jdk;
        chmod u+x /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh;
        /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /usr/share/wazuh-indexer/opensearch-security/ -nhnv -cacert /usr/share/wazuh-indexer/certs/root-ca.pem -cert /usr/share/wazuh-indexer/certs/admin.pem -key /usr/share/wazuh-indexer/certs/admin-key.pem -p 9200 -icl"

docker compose down
docker compose up -d
