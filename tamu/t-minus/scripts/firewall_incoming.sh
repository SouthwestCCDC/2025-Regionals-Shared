#!/bin/sh
set -e

tmux_notify_channel="$1"
machine_nickname="$2"
machine_ip_list="$3"
blueteam_ip_list="$4"

trap "tmux wait-for -S \"$tmux_notify_channel\"" EXIT

# Make the following firewall changes
# - allow between machines
# - allow between blue team machines
# - allow incoming to listening ports
# - allow outgoing established, related
script_sh="command -v sudo >/dev/null || { command -v doas >/dev/null && alias sudo=doas ; }
sudo sh -c '
set -e
systemctl disable --now ufw 2>/dev/null || true
systemctl disable --now firewalld 2>/dev/null || true
service awall stop 2>/dev/null || true
rc-update del awall 2>/dev/null || true
service ufw stop 2>/dev/null || true
rc-update del ufw 2>/dev/null || true

listen_ports_tcp=\"\$({ ss -Hnp -ltu 2>/dev/null || netstat -np -ltu | tail -n+1 ;} | grep \"tcp\" | awk \"{print \$5;}\" | grep -o \"[0-9]\\+$\" | sort -u)\"
listen_ports_udp=\"\$({ ss -Hnp -ltu 2>/dev/null || netstat -np -ltu | tail -n+1 ;} | grep \"udp\" | awk \"{print \$5;}\" | grep -o \"[0-9]\\+$\" | sort -u)\"

if command -v nft; then
    nft flush ruleset
    nft add table inet filter
    nft add chain inet filter input \"{ type filter hook input priority 0; }\"
    nft add chain inet filter forward \"{ type filter hook forward priority 0; }\"
    nft add chain inet filter output \"{ type filter hook output priority 0; }\"

    nft add rule inet filter input ip saddr 127.0.0.1 accept
    nft add rule inet filter input ct state established,related accept
    nft add rule inet filter output ip daddr 127.0.0.1 accept
    nft add rule inet filter output ct state established,related accept

    for machine in $blueteam_ip_list; do
        nft add rule inet filter input ip saddr \$machine accept comment \"\\\"Allow blue team access\\\"\"
        nft add rule inet filter output ip daddr \$machine accept comment \"\\\"Allow blue team access\\\"\"
    done
    for machine in $machine_ip_list; do
        nft add rule inet filter input ip saddr \$machine accept comment \"\\\"Allow accessing peer servers\\\"\"
        nft add rule inet filter output ip daddr \$machine accept comment \"\\\"Allow accessing peer servers\\\"\"
    done
    for port in \$listen_ports_tcp; do
        nft add rule inet filter input tcp dport \$port accept comment \"\\\"Allow accessing initial services\\\"\"
    done
    for port in \$listen_ports_udp; do
        nft add rule inet filter input udp dport \$port accept comment \"\\\"Allow accessing initial services\\\"\"
    done

    nft list ruleset > fw.bak
    nft add chain inet filter input \"{ policy drop; }\"
elif command -v iptables ; then
    iptables -F
    iptables -P INPUT ACCEPT
    iptables -P OUTPUT ACCEPT
    ip6tables -F
    ip6tables -P INPUT ACCEPT
    ip6tables -P OUTPUT ACCEPT

    iptables -A INPUT -s 127.0.0.1 -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -d 127.0.0.1 -j ACCEPT
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    for machine in $blueteam_ip_list; do
        iptables -A INPUT -s \$machine -j ACCEPT -m comment --comment \"Allow blue team access\"
        iptables -A OUTPUT -d \$machine -j ACCEPT -m comment --comment \"Allow blue team access\"
    done
    for machine in $machine_ip_list; do
        iptables -A INPUT -s \$machine -j ACCEPT -m comment --comment \"Allow accessing peer servers\"
        iptables -A OUTPUT -d \$machine -j ACCEPT -m comment --comment \"Allow accessing peer servers\"
    done
    for port in \$listen_ports_tcp; do
        iptables -A INPUT -p tcp --dport \$port -j ACCEPT -m comment --comment \"Allow accessing initial services\"
    done
    for port in \$listen_ports_udp; do
        iptables -A INPUT -p udp --dport \$port -j ACCEPT -m comment --comment \"Allow accessing initial services\"
    done

    iptables-save > fw.back
    iptables -P INPUT DROP
else
    printf \"No firewall found. Exiting\n\"
    exit
fi

# Restore permissive rules if ssh gets disconnected
sleep 20
if ! [ -f /tmp/fw_confirm ]; then
    if command -v iptables; then
        iptables -F
        iptables-restore < fw.bak
    elif command -v nft; then
        nft flush ruleset
        nft -f fw.bak
    fi
    exit
else
    rm /tmp/fw_confirm
fi
'"

printf "%s" "$script_sh" | ssh "$machine_nickname" /bin/sh -s &

sleep 5

load_rules='if command -v nft; then nft flush ruleset; nft -f /etc/nftables.conf ; else iptables -F; iptables-restore < /etc/iptables/rules.v4; ip6tables -F; ip6tables-restore < /etc/iptables/rules.v6 ; fi'

# Make sure it's still possible to reach the machine with the firewall configuration
script2_sh="
command -v sudo >/dev/null || { command -v doas >/dev/null && alias sudo=doas ; }
sudo sh -c '
set -e
touch /tmp/fw_confirm
printf \"Machine is reachable\n\"
printf \"Saving firewall rules persistently\n\"
mkdir -p /etc/sysconfig
if command -v nft; then
    nft list ruleset > /etc/nftables.conf
    nft list ruleset > /etc/sysconfig/nftables.conf
elif command -v iptables; then
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6
    iptables-save > /etc/sysconfig/iptables
    ip6tables-save > /etc/sysconfig/ip6tables
fi
if command -v systemctl; then
    service_exists=0
    if command -v nft; then
        systemctl enable nftables 2>/dev/null && service_exists=1
    elif command -v iptables; then
        systemctl enable iptables 2>/dev/null && service_exists=1
        systemctl enable iptables-persistent 2>/dev/null && service_exists=1
    fi
    if [ 0 = \"\$service_exists\" ]; then
        printf \"Missing firewall services, adding firewall restore rules to custom restore-firewall-rules.service\n\"
        cat <<EOF > /etc/systemd/system/restore-firewall-rules.service
[Unit]
Description=Restore firewall rules on boot
Wants=network-pre.target
Before=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c \"$load_rules\"
ExecReload=/bin/sh -c \"$load_rules\"

[Install]
WantedBy=sysinit.target
EOF
        systemctl enable restore-firewall-rules
    fi
elif grep -q \"alpine\" /etc/os-release; then
    if command -v nft; then
        rc-update add nftables
        rc-service nftables save
    elif command -v iptables; then
        rc-update add iptables
        rc-service iptables save
        rc-update add ip6tables
        rc-service ip6tables save
    fi
else
    printf \"Unknown OS, adding firewall restore rules to /etc/rc.local\"
    printf \"%s\" \"$load_rules\" >> /etc/rc.local
fi
'"

printf "Confirming machine is still reachable\n"
printf "%s" "$script2_sh" | ssh -o ConnectTimeout=7 "$machine_nickname" /bin/sh -s
