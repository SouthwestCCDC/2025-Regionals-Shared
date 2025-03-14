#!/bin/sh
set -e

tmux_notify_channel="$1"
machine_nickname="$2"
username="$3"

trap "tmux wait-for -S \"$tmux_notify_channel\"" EXIT

test_sh="
id
sudo -n true 2>/dev/null || doas -n true 2>/dev/null
echo $?
"

result="$(printf "%s" "$test_sh" | ssh "$machine_nickname" /bin/sh -s)"

# Verify the user is a nopasswd sudo user
if ! { echo "$result" | grep -q "$username" && echo "$result" | grep -q "^0$" ; }; then
    printf "Unable to sign in as $username, or user is not a nopasswd sudoer/doas-er" >&2
    exit 1
fi
