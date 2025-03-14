#!/bin/sh
set -e

host="$1"
username="$2"
password="$3"
machine_ip="$4"

test -n "$host"
test -n "$username"
test -n "$password"
test -n "$machine_ip"

trap "tmux wait-for -S \"$tmux_notify_channel\"" EXIT

# Log in and get a session cookie
printf "Logging in\n" >&2
basic_auth="$(printf "%s:%s" "$username" "$password" | base64)"
cookie="$(curl "$host/login" -s -X POST -c - -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' -H "Authorization: Basic $basic_auth" --data-raw 'remember=false&two_factor_auth_token=' | grep '^#HttpOnly.*sunstone' | awk '{print $7;}')"
csrftoken="$(curl "$host" -s -H "Cookie: sunstone=$cookie" | grep 'var csrftoken = ' | cut -d"'" -f2)"

# Create a list of VMs to restore
if [ "$machine_ip" = "*" ]; then
    vm_list_json="$(curl "$host/vm?timeout=false&pool_filter=-2&csrftoken=$csrftoken" -s -H "Cookie: sunstone=$cookie" | jq -c '.VM_POOL.VM[] | {"id": .ID, "name": .NAME}')"
else
    vm_list_json="$(curl "$host/vm?timeout=false&pool_filter=-2&csrftoken=$csrftoken" -s -H "Cookie: sunstone=$cookie" | jq -c '.VM_POOL.VM[] | {"id": .ID, "name": .NAME, "ip": (.TEMPLATE.NIC | if type=="null" then [] elif type=="array" then . else [.] end | .[].IP) } | select(.ip == "'"$machine_ip"'")')"
fi

# Access input when in while read loop
exec 3</dev/tty || exec 3<&0

printf "%s\n" "$vm_list_json" |
while IFS= read -r machine_json; do
    id="$(printf "%s\n" "$machine_json" | jq -r '"\(.id)"')"
    name="$(printf "%s\n" "$machine_json" | jq '"\(.name)"')"

    printf "All snapshots for %s:\n" "$name"
    printf -- "--------------------------------------------------------------------------------\n"

    snapshot_list_json="$(curl "$host/vm/$id?timeout=false&pool_filter=-2&csrftoken=$csrftoken" -s -H "Cookie: sunstone=$cookie" | jq -c '.VM.TEMPLATE.SNAPSHOT | if type=="null" then [] elif type=="array" then . else [.] end | .[]')"

    printf "DATE               \tID\tNAME\n"
    printf "%s\n" "$snapshot_list_json" |
    while IFS= read -r snapshot_json; do
        printf "%s\n" "$snapshot_json" | jq -r '"\(.TIME | strptime("%s") | strftime("%Y-%m-%d %H:%M:%S"))\t\(.SNAPSHOT_ID)\t\(.NAME)"'
    done
    printf -- "--------------------------------------------------------------------------------\n"

    while true; do
        printf "Enter ID to restore %s to (or s to skip): " "$name"
        IFS= read -r restore_id <&3
        printf "restore_id: '%s'\n" "$restore_id"

        if [ -z "$restore_id" ] && { printf "%s" "$restore_id" | grep -q '[^0-9]' && [ "s" != "$restore_id" ] ; } ; then
            printf "Invalid ID\n";
            continue
        fi

        if [ "s" = "$restore_id" ]; then
            printf "Skipping\n"
            break
        fi

        printf "\nRestoring %s to snapshot %s\n" "$name" "$restore_id"
        restore_result="$(curl "$host/vm/$id/action" -s -X POST -H 'Content-Type: application/json; charset=utf-8' -H "Cookie: sunstone=$cookie" --data-raw '{"action":{"perform":"snapshot_revert","params":{"snapshot_id":"'$restore_id'"}},"csrftoken":"'$csrftoken'"}')"

        if ! printf "%s" "$restore_result" | grep -q 'error'; then
            printf "Done.\n"
            break
        else
            printf "Failure.\n%s\n" "$restore_result"
        fi
    done

done

exec 3<&-

# Logout
printf "Logging out\n" >&2
curl "$host/logout" -X POST -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' -H "Cookie: sunstone=$cookie" --data-raw "csrftoken=$csrftoken"
