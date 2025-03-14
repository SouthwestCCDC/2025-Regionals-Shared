#!/bin/sh
set -e

tmux_notify_channel="$1"
machine_nickname="$2"

trap "tmux wait-for -S \"$tmux_notify_channel\"" EXIT

script_sh="command -v sudo >/dev/null || { command -v doas >/dev/null && alias sudo=doas ; }
sudo sh -c '
find /etc/anacron* /etc/cron* /etc/default/cron /etc/incron* /etc/periodic /var/spool/anacron /var/spool/cron -type f -exec sh -c \"printf \\\"\\n\\n------\\n\\\"; echo file: {}; cat {}\" \\; 2>/dev/null || true
'"

printf "%s" "$script_sh" | ssh "$machine_nickname" /bin/sh -s
