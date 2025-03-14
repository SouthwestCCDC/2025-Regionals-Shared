#!/bin/sh
set -e

tmux_notify_channel="$1"
tmux_target="$2"
tmux_window_name="$3"
machine_nickname="$4"
dont_change_userlist="$5"

trap "tmux rename-window -t \"$tmux_session_name:![prompt]$tmux_window_name\" \"$tmux_window_name\" ; tmux wait-for -S \"$tmux_notify_channel\"" EXIT

tmux rename-window -t "$tmux_session_name:$tmux_window_name" "![prompt]$tmux_window_name"

script_sh="command -v sudo >/dev/null || { command -v doas >/dev/null && alias sudo=doas ; }
sudo sh -c '
dont_change_args=\"\"
for user in $dont_change_userlist; do
    dont_change_args=\"\$dont_change_args -e ^\$user\"
done
changelist=\"\"
for user in \$(cat /etc/passwd | cut -d: -f1 | sort | grep -vx \$dont_change_args); do
    if command -v apg >/dev/null; then
        pass=\"\$(apg -n 1 -m 10 -x 12 -a 0 -M SNCL -E :,)\"
    else
        pass=\"\$(dd if=/dev/urandom bs=1 count=12 2>/dev/null | base64)\"
    fi
    changelist=\"\$changelist\$user,\$pass\\n\"
done
printf \"\$changelist\"
'"
changelist="$(printf "%s" "$script_sh" | ssh "$machine_nickname" /bin/sh -s)"

printf -- '--------------------------------------------------------------------------------\n'
printf '%s\n' "$changelist"
printf -- '--------------------------------------------------------------------------------\n'

while true; do
    printf "Set these passwords? [y/n] "
    read -r prompt_ans

    case "$prompt_ans" in
        y|Y)
            break
            ;;
        n|N)
            exit 1
            ;;
        *)
            continue
            ;;
    esac
done

script2_sh="command -v sudo || { command -v doas && alias sudo=doas ; }
sudo sh -c '
unset HISTFILE
cat | chpasswd <<EOF
$(printf "$changelist" | sed "s/,/:/")
EOF
'"

printf "%s" "$script2_sh" | ssh "$machine_nickname" /bin/sh -s
