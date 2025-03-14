#!/bin/sh
set -e

host="$1"
username="$2"
password="$3"

test -n "$host"
test -n "$username"
test -n "$password"

trap "tmux wait-for -S \"$tmux_notify_channel\"" EXIT

# Log in and get a session cookie
printf "Logging in\n" >&2
basic_auth="$(printf "%s:%s" "$username" "$password" | base64)"
cookie="$(curl "$host/login" -s -X POST -c - -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' -H "Authorization: Basic $basic_auth" --data-raw 'remember=false&two_factor_auth_token=' | grep '^#HttpOnly.*sunstone' | awk '{print $7;}')"
csrftoken="$(curl "$host" -s -H "Cookie: sunstone=$cookie" | grep 'var csrftoken = ' | cut -d"'" -f2)"

# Get list of IP addresses
curl "$host/vm?timeout=false&pool_filter=-2&csrftoken=$csrftoken" -s -H "Cookie: sunstone=$cookie" | jq -r '.VM_POOL.VM[].TEMPLATE.NIC | if type=="null" then [] elif type=="array" then . else [.] end | .[].IP'

# Logout
printf "Logging out\n" >&2
curl "$host/logout" -X POST -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' -H "Cookie: sunstone=$cookie" --data-raw "csrftoken=$csrftoken"
