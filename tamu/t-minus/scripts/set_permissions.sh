#!/bin/sh
set -e

tmux_notify_channel="$1"
machine_nickname="$2"

trap "tmux wait-for -S \"$tmux_notify_channel\"" EXIT

script_sh="command -v sudo >/dev/null || { command -v doas >/dev/null && alias sudo=doas ; }
sudo sh -c '
chown root:root /*
chmod -c -f o-w /*
chmod -c -f o-w /usr/*
chmod -c -f -R o-w /etc/*
chmod -c -f 1777 /tmp /usr/tmp

chown root:root /etc/passwd /etc/passwd- /etc/group /etc/group- /etc/shadow /etc/shadow- /etc/gshadow /etc/gshadow-
chmod 0644 /etc/passwd /etc/passwd- /etc/group /etc/group-
chmod 0600 /etc/shadow /etc/shadow- /etc/gshadow /etc/gshadow-

chown root:root /var/log
chmod 0700 /var/log

chown root:root /etc/ssh/sshd_config /etc/ssh/sshd_config.d
chmod 0600 /etc/ssh/sshd_config /etc/ssh/sshd_config.d

chown root:root /etc/sudoers /etc/sudoers.d
chmod 0600 /etc/sudoers /etc/sudoers.d

chmod 700 /home/*
'"

printf "%s" "$script_sh" | ssh "$machine_nickname" /bin/sh -s
