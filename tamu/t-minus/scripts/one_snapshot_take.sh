#!/bin/sh
set -e

host="$1"
username="$2"
password="$3"
machine_ip="$4"
snapshot_name="$5"

test -n "$host"
test -n "$username"
test -n "$password"
test -n "$machine_ip"
test -n "$snapshot_name"

trap "tmux wait-for -S \"$tmux_notify_channel\"" EXIT

# Log in and get a session cookie
printf "Logging in\n" >&2
basic_auth="$(printf "%s:%s" "$username" "$password" | base64)"
cookie="$(curl "$host/login" -s -X POST -c - -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' -H "Authorization: Basic $basic_auth" --data-raw 'remember=false&two_factor_auth_token=' | grep '^#HttpOnly.*sunstone' | awk '{print $7;}')"
csrftoken="$(curl "$host" -s -H "Cookie: sunstone=$cookie" | grep 'var csrftoken = ' | cut -d"'" -f2)"

# Create a list of VMs to back up
if [ "$machine_ip" = "*" ]; then
    vm_list_json="$(curl "$host/vm?timeout=false&pool_filter=-2&csrftoken=$csrftoken" -s -H "Cookie: sunstone=$cookie" | jq -c '.VM_POOL.VM[] | {"id": .ID, "name": .NAME, "ips": .VM_POOL.VM[].TEMPLATE.NIC | if type=="null" then [] elif type=="array" then . else [.] end | .[].IP }')"
else
    vm_list_json="$(curl "$host/vm?timeout=false&pool_filter=-2&csrftoken=$csrftoken" -s -H "Cookie: sunstone=$cookie" | jq -c '.VM_POOL.VM[] | {"id": .ID, "name": .NAME, "ip": (.TEMPLATE.NIC | if type=="null" then [] elif type=="array" then . else [.] end | .[].IP) } | select(.ip == "'"$machine_ip"'")')"
fi

snapshots_failed=0

printf "%s\n" "$vm_list_json" |
while IFS= read -r machine_json; do
    id="$(printf "%s\n" "$machine_json" | jq -r '"\(.id)"')"
    ip="$(printf "%s\n" "$machine_json" | jq -r '"\(.ip)"')"
    name="$(printf "%s\n" "$machine_json" | jq '"\(.name)"')"

    printf '\nTaking snapshot for %s (%s) with snapshot name "%s"\n' "$name" "$ip" "$snapshot_name"
    snapshot_result="$(curl "$host/vm/$id/action" -s -X POST -H 'Content-Type: application/json; charset=utf-8' -H "Cookie: sunstone=$cookie" --data-raw '{"action":{"perform":"snapshot_create","params":{"snapshot_name":"'"$snapshot_name"'"}},"csrftoken":"'$csrftoken'"}')"

    if ! printf "%s" "$snapshot_result" | grep -q 'error'; then
        printf "\nDone.\n"
    else
        printf "\nFailure.\n%s\n" "$snapshot_result"
        snapshots_failed=1
    fi
    printf "All snapshots for %s:\n" "$name"
    printf -- "--------------------------------------------------------------------------------\n"

    snapshot_list_json="$(curl "$host/vm/$id?timeout=false&pool_filter=-2&csrftoken=$csrftoken" -s -H "Cookie: sunstone=$cookie" | jq -c '.VM.TEMPLATE.SNAPSHOT | if type=="null" then [] elif type=="array" then . else [.] end | .[]')"

    printf "DATE               \tID\tNAME\n"
    printf "%s\n" "$snapshot_list_json" |
    while IFS= read -r snapshot_json; do
        printf "%s\n" "$snapshot_json" | jq -r '"\(.TIME | strptime("%s") | strftime("%Y-%m-%d %H:%M:%S"))\t\(.SNAPSHOT_ID)\t\(.NAME)"'
    done
    printf -- "--------------------------------------------------------------------------------\n"
done

# Logout
printf "Logging out\n" >&2
curl "$host/logout" -X POST -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' -H "Cookie: sunstone=$cookie" --data-raw "csrftoken=$csrftoken"

if [ "$snapshots_failed" = "1" ]; then
    exit 1
fi
