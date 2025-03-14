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
    dpkg --verify
elif echo \"\$os_type\" | grep -q -e \"rhel\" -e \"fedora\" -e \"centos\" -e \"suse\"; then
    rpm -Va || true
elif echo \"\$os_type\" | grep -q \"alpine\"; then
    apk audit
elif echo \"\$os_type\" | grep -q \"arch\"; then
    pacman -Qkk
fi
'"

printf "%s" "$script_sh" | ssh "$machine_nickname" /bin/sh -s

printf '

The above list is all packages that have been modified from disto defaults.

Verify Code Meaning (dpkg, rpm)
  S    File size differs.
  M    File mode differs (includes permissions and file type).
  5    The MD5 checksum differs.
  D    The major and minor version numbers differ on a device file.
  L    A mismatch occurs in a link.
  U    The file ownership differs.
  G    The file group owner differs.
  T    The file time (mtime) differs.

Verify Code Meaning (alpine)
  +   On-disk detail record
  A   File added
  d   Directory added
  D   Directory added (with non-listed files/subdirs)
  e   error occured during audit (e.g. no permissions to read file)
  M   File metadata changed (uid, gid, or mode)
  m   Directory metadata changed
  U   File contents modified
  X   File deleted
  x   xattrs changed
'
