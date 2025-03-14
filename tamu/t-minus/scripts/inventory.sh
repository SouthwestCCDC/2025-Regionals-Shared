#!/bin/sh
set -e

tmux_notify_channel="$1"
machine_ip="$2"
machine_nickname="$3"
inventory_dir="$4"

trap "tmux wait-for -S \"$tmux_notify_channel\"" EXIT

mkdir -p "$inventory_dir"

inventory_sh="
command -v sudo >/dev/null || { command -v doas >/dev/null && alias sudo=doas ; }
inventory() {
  printf -- '--------------------------------------------------------------------------------\n' 
  printf 'Hostname: '
  hostname 2>/dev/null || uname -n 2>/dev/null || cat /etc/hostname 2>/dev/null || echo 'unknown'

  printf 'OS: '
  cat /etc/os-release | grep ^PRETTY_NAME | cut -d'\"' -f2

  printf 'Kernel: '
  uname -a

  printf 'IP addresses:\n'
  ip address | grep inet

  printf 'Listening services:\n'
  { sudo ss -lnptu 2>/dev/null || sudo netstat -lnptu ; } | sed 's/^/    /'
  printf -- '--------------------------------------------------------------------------------\n' 
}
inventory
"

printf "%s" "$inventory_sh" | ssh "$machine_nickname" /bin/sh -s > "$inventory_dir/$machine_ip"
