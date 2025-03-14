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

if echo \"\$os_type\" | grep -q -e \"debian\" -e \"ubuntu\"; then
    apt-get update
    apt-get upgrade -y
elif echo \"\$os_type\" | grep -q -e \"rhel\" -e \"fedora\" -e \"centos\"; then
    if command -v dnf; then
        dnf upgrade -y
    else
        yum update -y
    fi
elif echo \"\$os_type\" | grep -q \"alpine\"; then
    # https://wiki.alpinelinux.org/wiki/Alpine_Package_Keeper
    apk update
    apk upgrade
elif echo \"\$os_type\" | grep -q \"suse\"; then
    # https://en.opensuse.org/System_Updates
    if echo \"\$os_type\" | grep -q \"tumbleweed\"; then
        zypper --non-interactive dup
    else
        zypper --non-interactive up
    fi
elif echo \"\$os_type\" | grep -q \"arch\"; then
    # https://wiki.archlinux.org/title/Pacman
    pacman -Syu
elif echo \"\$os_type\" | grep -q \"slackware\"; then
    # https://docs.slackware.com/slackware:package_management_hands_on
    slackpkg upgrade-all
elif echo \"\$os_type\" | grep -q \"gentoo\"; then
    # https://wiki.gentoo.org/wiki/Upgrading_Gentoo
    emaint --auto sync
    emerge --verbose --update --deep --newuser @world
else
    printf \"Unknown OS\n\"
fi
'"

printf "%s" "$script_sh" | ssh "$machine_nickname" /bin/sh -s
