#!/bin/sh
set -e

tmux_notify_channel="$1"
tmux_session_name="$2"
tmux_window_name="$3"
machine_ip="$4"
machine_nickname="$5"
sandbox_dir="$6"

trap "tmux rename-window -t \"$tmux_session_name:![prompt]$tmux_window_name\" \"$tmux_window_name\" ; tmux wait-for -S \"$tmux_notify_channel\"" EXIT

tmux rename-window -t "$tmux_session_name:$tmux_window_name" "![prompt]$tmux_window_name"

current_time="$(date +%Y-%m-%d__%H:%M:%S)"
mkdir -p "$sandbox_dir/$machine_ip/$current_time"

scp -r "scripts/resources/sandbox" "$machine_nickname:~"

printf "Run 'cd sandbox; sudo sh sandbox.sh' until all services are sandboxed, then exit\n"
ssh -t "$machine_nickname"

scp -r "$machine_nickname:~/sandbox/sandbox_configs/*" "$sandbox_dir/$machine_ip/$current_time"
