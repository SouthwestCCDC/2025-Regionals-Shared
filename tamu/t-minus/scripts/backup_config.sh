#!/bin/sh
set -e

tmux_notify_channel="$1"
machine_ip="$2"
machine_nickname="$3"
username="$4"
backup_dir="$5"

trap "tmux wait-for -S \"$tmux_notify_channel\"" EXIT

current_time="$(date +%Y-%m-%d__%H:%M:%S)"
mkdir -p "$backup_dir/$machine_ip/$current_time"

backup_sh="command -v sudo >/dev/null || { command -v doas >/dev/null && alias sudo=doas ; }
sudo sh -c '
mkdir -p backup_network
iptables-save > backup_network/fw_iptables.conf    2>/dev/null
ip6tables-save > backup_network/fw_ip6tables.conf  2>/dev/null
nft list ruleset > backup_network/fw_nftables.conf 2>/dev/null
ip a > backup_network/ip_a.txt
nmcli > backup_network/nmcli.txt 2>/dev/null
nmcli device show > backup_network/nmcli_dev.txt 2>/dev/null
tar -cf backup_network.tar backup_network
find /root /home -name \".*hist*\" -exec tar -cvf backup_history.tar {} +
tar -cf backup_etc.tar /etc
find /var \! \\( -path \"/var/lib/apt/lists/*\" -o -path \"/var/cache/*\" -o -path \"/var/log/journal/*\" -o -path \"/var/lib/texmf/*\" \\) -exec tar -cf backup_var.tar {} +
chown $username:$username backup_network.tar
chown $username:$username backup_history.tar
chown $username:$username backup_etc.tar
chown $username:$username backup_var.tar
'
"

printf "%s" "$backup_sh" | ssh "$machine_nickname" /bin/sh -s

scp "$machine_nickname":backup_network.tar "$backup_dir/$machine_ip/$current_time" || printf "No such file: backup_network.tar\n"
scp "$machine_nickname":backup_history.tar "$backup_dir/$machine_ip/$current_time" || printf "No such file: backup_history.tar\n"
scp "$machine_nickname":backup_etc.tar "$backup_dir/$machine_ip/$current_time" || printf "No such file: backup_etc.tar\n"
scp "$machine_nickname":backup_var.tar "$backup_dir/$machine_ip/$current_time" || printf "No such file: backup_var.tar\n"
