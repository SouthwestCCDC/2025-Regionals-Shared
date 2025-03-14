#!/bin/sh
set -e

tmux_notify_channel="$1"
machine_nickname="$2"

trap "tmux wait-for -S \"$tmux_notify_channel\"" EXIT

script_sh="command -v sudo >/dev/null || { command -v doas >/dev/null && alias sudo=doas ; }
sudo sh -c '
set -e
# Get both ID and ID_LIKE fields
os_type=\"\$(cat /etc/os-release | grep ^ID | cut -d\"\\\"\" -f2)\"

if echo \"\$os_type\" | grep -q -e \"debian\" -e \"ubuntu\"; then
    apt-get -y install fail2ban
    systemctl enable --now fail2ban
elif echo \"\$os_type\" | grep -q -e \"rhel\" -e \"fedora\" -e \"centos\"; then
    if command -v dnf; then
        dnf -y install fail2ban
    else
        yum -y install fail2ban
    fi
    systemctl enable --now fail2ban
elif echo \"\$os_type\" | grep -q \"suse\"; then
    # https://en.opensuse.org/System_Updates
    zypper --non-interactive install fail2ban
    systemctl enable --now fail2ban
elif echo \"\$os_type\" | grep -q \"alpine\"; then
    apk add fail2ban
    rc-update add fail2ban
    service fail2ban start
elif echo \"\$os_type\" | grep -q \"arch\"; then
    pacman -S fail2ban
    systemctl enable --now fail2ban
fi
'"

printf "%s" "$script_sh" | ssh "$machine_nickname" /bin/sh -s
