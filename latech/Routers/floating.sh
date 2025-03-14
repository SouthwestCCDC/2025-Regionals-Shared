#!/bin/vbash

#Load Vyos CLI API
source /opt/vyatta/etc/functions/script-template

#Enter configuration mode
configure

#Define Network and Port groups

export OUR_NETWORKS="10.0.1.0/24 10.0.2.0/24 172.31.80.0/24 172.31.255.17/32 172.31.255.18/32 172.69.1.0/24 172.20.224.0/24"
export BLUE_NETWORK="10.0.1.0/24 10.0.2.0/24 172.31.255.17/32 172.69.1.0/24"
export ROUTER_NETWORKS="172.31.255.17/32 172.31.255.18/32"

for network in $OUR_NETWORKS; 
do set firewall group network-group OurNetworks network $network
done
for network in $BLUE_NETWORK; 
do set firewall group network-group BlueTeam network $network
done
for network in $ROUTER_NETWORKS; 
do set firewall group network-group INNetworks network $network
done

#Define known private cidr ranges to prevetn IP spoofing attacks
set firewall group network-group RFC1918CIDRS network 10.0.0.0/8
set firewall group network-group RFC1918CIDRS network 172.16.0.0/12
set firewall group network-group RFC1918CIDRS network 192.168.0.0/16
set firewall group network-group RFC1918CIDRS network 127.0.0.0/8
set firewall group network-group RFC1918CIDRS network 169.254.0.0/16
#multi-cast cidr range
set firewall group network-group RFC1918CIDRS network 224.0.0.0/4

#Define AD ports
for port in 22 137 3389 5985 5986
do
set firewall group port-group MGMT port $port
done

#Define Management ports
for port in 53 88 135 137 138 139 389 443 445 464 636 3268 3269 49443
do
set firewall group port-group AD port ${port}
done

export KEYS=""

#SSH CONFIGURAITION
for sshconf in $KEYS:
do 
    name=$(echo -n $sshconf | cut -d ':' -f 1)
    key=$(echo -n $sshconf | cut -d ':' -f 2)
    set system login user vyos authentication public-keys $name type ssh-rsa
    set system login user vyos authentication public-keys $name key $key
done

set service ssh disable-password-authentication
set service ssh dynamic-protection allow-from Blue_Team
set service ssh dynamic-protection block-time '120'
set service ssh dynamic-protection detect-time '1800'
set service ssh dynamic-protection threshold '30'
set service ssh port '22'

#FLOATING RULE SETS AND NETWORK GROUPS
set firewall name FLOATING default-action accept

set firewall name FLOATING rule 5 action accept
set firewall name FLOATING rule 5 state established enable
set firewall name FLOATING rule 5 state related enable

set firewall name FLOATING rule 10 description 'Block ICMP not from BlueTeam'
set firewall name FLOATING rule 10 action drop
set firewall name FLOATING rule 10 log enable
set firewall name FLOATING rule 10 protocol ICMP
set firewall name FLOATING rule 10 destination group network-group OurNetworks
set firewall name FLOATING rule 10 source group network-group !BlueTeam

set firewall name FLOATING rule 15 description 'Allow ICMP from Blueteam'
set firewall name FLOATING rule 15 action accept
set firewall name FLOATING rule 15 protocol ICMP
set firewall name FLOATING rule 15 destination group network-group OurNetworks
set firewall name FLOATING rule 15 source group network-group BlueTeam

set firewall name FLOATING rule 20 description 'Block all not from our network range'
set firewall name FLOATING rule 20 action drop
set firewall name FLOATING rule 20 log enable
set firewall name FLOATING rule 20 protocol tcp_udp
set firewall name FLOATING rule 20 destination group port-group MGMT
set firewall name FLOATING rule 20 source group network-group !BlueTeam

set firewall name FLOATING rule 25 description 'Allow all from blueteam range to management ports'
set firewall name FLOATING rule 25 action accept
set firewall name FLOATING rule 25 log enable
set firewall name FLOATING rule 25 protocol tcp_udp
set firewall name FLOATING rule 25 destination group port-group MGMT
set firewall name FLOATING rule 25 source group network-group BlueTeam

set firewall name FLOATING rule 30 description 'Block all not from our network range'
set firewall name FLOATING rule 30 action drop
set firewall name FLOATING rule 30 log enable
set firewall name FLOATING rule 30 protocol tcp_udp
set firewall name FLOATING rule 30 destination group port-group AD
set firewall name FLOATING rule 30 destination group network-group OurNetworks
set firewall name FLOATING rule 30 source group network-group !OurNetworks

set firewall name FLOATING rule 35 description 'Allow all from our network range to our network range'
set firewall name FLOATING rule 35 action accept
set firewall name FLOATING rule 35 protocol tcp_udp
set firewall name FLOATING rule 35 destination group port-group AD
set firewall name FLOATING rule 35 destination group network-group OurNetworks
set firewall name FLOATING rule 35 source group network-group OurNetworks



#Ingress rules for routers
set firewall name INGRESS default-action accept

set firewall name INGRESS rule 5 action accept
set firewall name INGRESS rule 5 state established enable
set firewall name INGRESS rule 5 state related enable

set firewall name INGRESS rule 10 description 'Block ICMP not from Our Networks'
set firewall name INGRESS rule 10 action drop
set firewall name INGRESS rule 10 log enable
set firewall name INGRESS rule 10 protocol ICMP
set firewall name INGRESS rule 10 destination group network-group INNetworks
set firewall name INGRESS rule 10 source group network-group !INNetworks

set firewall name INGRESS rule 20 description 'Block all not from our network range'
set firewall name INGRESS rule 20 action drop
set firewall name INGRESS rule 20 log enable
set firewall name INGRESS rule 20 protocol tcp_udp
set firewall name INGRESS rule 20 destination group port-group MGMT
set firewall name INGRESS rule 20 source group network-group !INNetworks

set firewall name INGRESS rule 30 description 'Block all not from our network range'
set firewall name INGRESS rule 30 action drop
set firewall name INGRESS rule 30 log enable
set firewall name INGRESS rule 30 protocol tcp_udp
set firewall name INGRESS rule 30 destination group port-group AD
set firewall name INGRESS rule 30 destination group network-group OurNetworks
set firewall name INGRESS rule 30 source group network-group !OurNetworks


#LOCAL FIREWALL RULSET (I.E. to the router)
set firewall name LOCAL default-action accept

set firewall name LOCAL rule 5 action accept
set firewall name LOCAL rule 5 state established enable
set firewall name LOCAL rule 5 state related enable

set firewall name LOCAL rule 10 description 'Block ssh not from Blueteam'
set firewall name LOCAL rule 10 action drop
set firewall name LOCAL rule 10 log enable
set firewall name LOCAL rule 10 protocol tcp
set firewall name LOCAL rule 10 destination port 22
set firewall name LOCAL rule 10 source group network-group !BlueTeam

set firewall name LOCAL rule 20 description 'Block DNS not from OurNetworks'
set firewall name LOCAL rule 20 action drop
set firewall name LOCAL rule 20 log enable
set firewall name LOCAL rule 20 protocol tcp_udp
set firewall name LOCAL rule 20 destination port 53
set firewall name LOCAL rule 20 source group network-group !OurNetworks

set firewall name LOCAL rule 30 description 'Block all not from Blueteam'
set firewall name LOCAL rule 30 action drop
set firewall name LOCAL rule 30 log enable
set firewall name LOCAL rule 30 protocol tcp_udp
set firewall name LOCAL rule 30 source group network-group !BlueTeam


#Commit and save to current running config
commit
save
