#!/bin/sh
set -e

tmux_notify_channel="$1"
tmux_session_name="$2"
tmux_window_name="$3"
prompt_message="$4"

trap "tmux rename-window -t \"$tmux_session_name:![prompt]$tmux_window_name\" \"$tmux_window_name\" ; tmux wait-for -S \"$tmux_notify_channel\"" EXIT

tmux rename-window -t "$tmux_session_name:$tmux_window_name" "![prompt]$tmux_window_name"

printf "\n\n%s: " "$prompt_message"
read -r prompt_ans

printf "\n%s\n" "$prompt_ans"
