#!/bin/sh
set -e

tmux_notify_channel="$1"
tmux_target="$2"
tmux_window_name="$3"
machine_ip="$4"
machine_nickname="$5"
logtime="$6"
dir="$7"

trap "tmux wait-for -S \"$tmux_notify_channel\"" EXIT

script_sh="command -v sudo >/dev/null || { command -v doas >/dev/null && alias sudo=doas ; }
sudo sh -c '
set -e
umask 0077
systemd-resolve --flush-caches >/dev/null 2>&1 || true
resolvectl flush-caches >/dev/null 2>&1 || true
tcpdump -t -nn -s 50 ip > conn.log &
p1=\$!
tcpdump -t -nn port 53 > dns.log &
p2=\$!
date
printf \"Logging traffic for $logtime seconds...\n\" >&2
sleep $logtime
kill \"\$p1\"
kill \"\$p2\"
printf \"Done.\n\" >&2
'"

# Get IP addresses and hostnames in /etc/hosts format
script2_sh="command -v sudo >/dev/null || { command -v doas >/dev/null && alias sudo=doas ; }
sudo sh -c '
set -e
cat conn.log | cut -d\">\" -f2 | cut -d\" \" -f2 | cut -d: -f1 | cut -d. -f-4 | sort -u | \
while read -r ip; do
    if printf \"%s\" \"\$ip\" | grep -q \"^[0-9]\"; then
        printf \"%s\t\" \"\$ip\"

        send_pair=\"\$(grep \"A \$ip\" dns.log | cut -d\">\" -f2 | cut -d\" \" -f2 | cut -d: -f1)\"
        if printf \"%s\" \"\$send_pair\" | grep -q \"^[0-9]\"; then
            grep \"\$send_pair >\" dns.log | grep -o \" A?.*\" | cut -d\" \" -f3 | sort -u | \
            while read -r name; do
                printf \"%s \" \"\${name%.}\"
            done
        fi
        printf \"\n\"
    fi
done
'"

printf "%s" "$script_sh" | ssh "$machine_nickname" /bin/sh -s

hosts="# These are the hosts that were connected to in the last $logtime seconds.
# These will be added to /etc/hosts and allowed in output firewall rules.
# Remove any that shouldn't be reachable from this machine.
$(printf "%s" "$script2_sh" | ssh "$machine_nickname" /bin/sh -s)"

mkdir -p "$dir/$machine_ip"
hostsfile="$dir/$machine_ip/new_hosts"
printf "%s" "$hosts" > "$hostsfile"


tmux rename-window -t "$tmux_session_name:$tmux_window_name" "![prompt]$tmux_window_name"

vim "$hostsfile"

cat "$hostsfile"

while true; do
    printf "%s\nAllow outbound access to only these hosts (deny everything else)? [y/n] " "$prompt_message"
    read -r prompt_ans

    case "$prompt_ans" in
        y|Y)
            break
            ;;
        n|N)
            printf "Skipping...\n"
            tmux rename-window -t "$tmux_session_name:![prompt]$tmux_window_name" "$tmux_window_name"
            exit 0
            ;;
        *)
            continue
            ;;
    esac
done

tmux rename-window -t "$tmux_session_name:![prompt]$tmux_window_name" "$tmux_window_name"

#iplist="$(cat "$hostsfile" | grep -v '^#' | cut -f1 | grep '[0-9]')"
hosts="$(cat "$hostsfile" | grep -v '^#' | grep '[0-9]')"

script3_sh="command -v sudo >/dev/null || { command -v doas >/dev/null && alias sudo=doas ; }
sudo sh -c '
set -e
printf \"%s\n\" \"$hosts\" >> /etc/hosts
printf \"%s\n\" \"$hosts\" | \
while IFS= read -r ip; do
    ip=\"\$(printf \"%s\" \"\$ip\" | cut -f1)\"
    host=\"\$(printf \"%s\" \"\$ip\" | cut -f2)\"
    if command -v nft >/dev/null; then
        nft add rule inet filter output ip daddr \"\$ip\" accept comment \"\\\"Allow logged outgoing connections: \$host\\\"\"
    elif command -v iptables >/dev/null; then
        iptables -A OUTPUT -d \"\$ip\" -j ACCEPT -m comment --comment \"Allow logged outgoing connections: \$host\"
    fi
done

printf \"%s\" \"Setting output policy to drop\n\" | \
if command -v nft >/dev/null; then
    nft list ruleset > fw.bak
    nft add chain inet filter output \"{ policy drop; }\"
elif command -v iptables >/dev/null; then
    iptables-save > fw.back
    iptables -P OUTPUT DROP
fi

# Restore permissive rules if ssh gets disconnected
sleep 20
if ! [ -f /tmp/fw_confirm ]; then
    if command -v iptables >/dev/null; then
        iptables -F
        iptables-restore < fw.bak
    elif command -v nft >/dev/null; then
        nft flush ruleset
        nft -f fw.bak
    fi
    exit
else
    rm /tmp/fw_confirm
fi
'"

printf "%s" "$script3_sh" | ssh "$machine_nickname" /bin/sh -s &

sleep 5

# Make sure it's still possible to reach the machine with the firewall configuration
script4_sh="
command -v sudo >/dev/null || { command -v doas >/dev/null && alias sudo=doas ; }
sudo sh -c '
set -e
touch /tmp/fw_confirm
printf \"Machine is reachable\n\"
printf \"Saving firewall rules persistently\n\"
if command -v nft >/dev/null; then
    nft list ruleset > /etc/nftables.conf
    nft list ruleset > /etc/sysconfig/nftables.conf
elif command -v iptables >/dev/null; then
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6
    iptables-save > /etc/sysconfig/iptables
    ip6tables-save > /etc/sysconfig/ip6tables
fi
if grep -q \"alpine\" /etc/os-release; then
    if command -v nft >/dev/null; then
        rc-service nftables save
    elif command -v iptables >/dev/null; then
        rc-service iptables save
        rc-service ip6tables save
    fi
fi
'"

printf "Confirming machine is still reachable\n"
printf "%s" "$script4_sh" | ssh -o ConnectTimeout=7 "$machine_nickname" /bin/sh -s
