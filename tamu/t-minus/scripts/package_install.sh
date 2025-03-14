#!/bin/sh
set -e

tmux_notify_channel="$1"
machine_nickname="$2"

trap "tmux wait-for -S \"$tmux_notify_channel\"" EXIT

script_sh="command -v sudo >/dev/null || { command -v doas >/dev/null && alias sudo=doas ; }
sudo sh -c '
set -e
# Check both ID and ID_LIKE fields
os_type=\"\$(cat /etc/os-release | grep ^ID | cut -d\"\\\"\" -f2)\"

iptables -P OUTPUT ACCEPT >/dev/null 2>&1 || true
nft add chain inet filter output \"{ policy accept; }\" 2>&1 || true

if echo \"\$os_type\" | grep -q -e \"debian\" -e \"ubuntu\"; then
    apt-get update
    apt-get -y install tcpdump vim
    if ! command -v nft 2>/dev/null; then
        apt-get -y install iptables iptables-persistent
    fi
elif echo \"\$os_type\" | grep -q -e \"rhel\" -e \"fedora\" -e \"centos\"; then
    if command -v dnf; then
        dnf -y install tcpdump vim
        if ! command -v nft 2>/dev/null; then
            dnf -y install iptables iptables-services
        fi
    else
        yum -y install tcpdump vim
        if ! command -v nft 2>/dev/null; then
            yum -y install iptables iptables-services
        fi
    fi
elif echo \"\$os_type\" | grep -q \"alpine\"; then
    # https://wiki.alpinelinux.org/wiki/Alpine_Package_Keeper
    apk update
    apk add tcpdump vim bubblewrap
    if ! command -v nft 2>/dev/null; then
        apk add iptables
    fi
elif echo \"\$os_type\" | grep -q \"suse\"; then
    # https://en.opensuse.org/System_Updates
    zypper --non-interactive install tcpdump vim
    if ! command -v nft 2>/dev/null; then
        zypper --non-interactive install iptables
    fi
elif echo \"\$os_type\" | grep -q \"arch\"; then
    # https://wiki.archlinux.org/title/Pacman
    pacman -S tcpdump vim
    if ! command -v nft 2>/dev/null; then
        pacman -S iptables
    fi
else
    printf \"Unknown OS\n\"
fi
'"

printf "%s" "$script_sh" | ssh "$machine_nickname" /bin/sh -s
