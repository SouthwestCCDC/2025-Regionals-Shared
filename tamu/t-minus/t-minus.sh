#!/bin/sh

# ------------------------------------------------------------------------------

# Ensure that all configuration values are set
set -e
test -n "$network_list"
test -n "$machine_list"
test -n "$blueteam_ip_list"
test -n "$opennebula_ip"
test -n "$opennebula_host"
test -n "$opennebula_username"
test -n "$opennebula_password"
test -n "$take_snapshots"
test -n "$username"
test -n "$password"
test -n "$new_username"
test -n "$new_password"
test -n "$fw_wait"
test -n "$dir_nmap"
test -n "$dir_inventory"
test -n "$dir_backup"
test -n "$dir_hosts"
test -n "$dir_sandbox"
test -n "$dir_record"

# Check for dependencies
dependency_list="
awk
curl
expect
jq
ssh
ssh-keygen
asciinema
tmux
vim
"
missing_dependency=0
for dep in $dependency_list; do
    command -v $dep >/dev/null || { echo "Missing $dep" && missing_dependency=1 ; }
done
if [ 1 = "$missing_dependency" ]; then
    exit 1
fi

tmux_session_name="ccdc"

# Reopen script in tmux
if [ -z "$TMUX" ]; then
    mkdir -p "$dir_record"
    cp tmux.conf ~/.tmux.conf
    tmux new -s "$tmux_session_name" -d
    sleep 1
    tmux source-file tmux.conf
    tmux rename-window -t "$tmux_session_name" "control"
    tmux send-keys -t "$tmux_session_name":control "$0" "$@" Enter
    asciinema rec "$dir_record/main.cast" -c "tmux attach -t $tmux_session_name:control"
    exit
fi

# Path where the ssh key for the new user will be retrieved from. If the file
# doesn't exist a new one will be generated with no passphrase
ssh_key_path=~/.ssh/id_ccdc_$new_username
if ! [ -f "$ssh_key_path" ]; then
    mkdir -p ~/.ssh
    chmod 700 ~/.ssh
    ssh-keygen -t ed25519 -f "$ssh_key_path" -N ""
fi

set +e

log_msg() {
    msg="$*"
    printf "%s %s\n" "$(date "+%Y-%m-%d %H:%M:%S")" "$msg" >&2
}

log_msg_machine() {
    machine="$1"
    shift
    msg="$*"
    log_msg "($machine): $msg"
}

snapshot_machine() {
    tmux_target="$1"
    tmux_wait_channel="$2"
    machine="$3"
    msg="$4"

    if [ 0 = "$take_snapshots" ]; then
        return 0
    fi

    log_msg_machine "$machine" "Taking snapshot - $msg"
    tmux send-keys -t "$tmux_target" \
        "sh scripts/one_snapshot_take.sh \"$opennebula_host\" \"$opennebula_username\" \"$opennebula_password\" \"$machine\" \"$msg\"; echo \$?" Enter;
    tmux wait-for "$tmux_wait_channel"

    results="$(tmux capture-pane -p -t "$tmux_target" | grep "." | tail -n2 | head -n1)"

    # Only continue if snapshot succeeded
    if [ 0 != "$results" ]; then
        log_msg_machine "$machine" "Failed to take a snapshot of the machine"
        tmux rename-window -t "$tmux_session_name:$tmux_window_name" "![error]$tmux_window_name"
        return 1
    fi
}

machine_script_run() {
    tmux_target="$1"
    tmux_wait_channel="$2" # Can be "" to skip waiting
    machine="$3"
    msg="$4"
    script="$5"
    for i in 1 2 3 4; do
        shift
    done

    log_msg_machine "$machine" "$msg"

    # Concatenate arguments to get the input tmux will send to the target pane
    tmux_arg="$script"
    while [ "0" != "$#" ]; do
        shift
        tmux_arg="$tmux_arg \"$1\""
    done
    tmux_arg="$tmux_arg ; echo \$?"

    tmux send-keys -t "$tmux_target" "$tmux_arg" Enter;

    if [ -n "$tmux_wait_channel" ]; then
        tmux wait-for "$tmux_wait_channel"
        sleep 1
    fi

    result_code="$(tmux capture-pane -p -t "$tmux_target" | grep "." | tail -n2 | head -n1)"
    #log_msg_machine "$machine" "$msg; Result: $result_code"
    return "$result_code"
}

prompt_user() {
    tmux_target="$1"
    tmux_wait_channel="$2"
    tmux_session_name="$3"
    tmux_window_name="$4"
    machine="$5"
    msg="$6"
    prompt="$7"

    log_msg_machine "$machine" "$msg"

    # Concatenate arguments to get the input tmux will send to the target pane
    tmux_arg="sh ./scripts/prompt_user.sh \"$tmux_wait_channel\" \"$tmux_session_name\" \"$tmux_window_name\" \"$prompt\"; echo \$?"

    tmux send-keys -t "$tmux_target" "$tmux_arg" Enter;

    if [ -n "$tmux_wait_channel" ]; then
        tmux wait-for "$tmux_wait_channel"
        sleep 1
    fi

    results="$(tmux capture-pane -p -t "$tmux_target" | grep "." | tail -n3 | head -n2)"
    result_code="$(echo "$results" | tail -n1)"
    result_prompt="$(echo "$results" | head -n1)"

    printf "%s\n" "$result_prompt"
    return "$result_code"
}

machine_service_check() {
    tmux_target="$1"
    tmux_wait_channel="$2"
    tmux_session_name="$3"
    tmux_window_name="$4"
    machine="$5"
    machine_name="$6"

    machine_script_run "$tmux_target" "$tmux_wait_channel" "$machine" "Prompting user to check service status" \
        "sh ./scripts/prompt_user_yn.sh" "$tmux_wait_channel" "$tmux_session_name" "$tmux_window_name" "Time: $(date). Check that all services for this machine \"$machine_name\" ($machine) are still up on the scoreboard. Press y if they are, n otherwise."

    if [ 0 = "$?" ]; then
        return 0
    fi

    log_msg_machine "$machine" "User indicated services not up"

    return 1
}

manual_fix() {
    tmux_target="$1"
    tmux_wait_channel="$2"
    tmux_session_name="$3"
    tmux_window_name="$4"
    machine="$5"
    step="$6"

    tmux send-keys -t "$tmux_target" 'printf "\n\nThe last step failed ('"$step"'). Use the left pane to fix it manually, then run \"tmux wait-for -S '"$tmux_wait_channel"'\"\n"' Enter

    log_msg_machine "$machine" "Waiting for user to fix issue"

    tmux rename-window -t "$tmux_session_name:$tmux_window_name" "![error]$tmux_window_name"

    tmux wait-for "$tmux_wait_channel"

    tmux rename-window -t "$tmux_session_name:![error]$tmux_window_name" "$tmux_window_name"

    machine_script_run "$tmux_target" "$tmux_wait_channel" "$machine" "Prompting user if issue has been fixed" \
        "sh ./scripts/prompt_user_yn.sh" "$tmux_wait_channel" "$tmux_session_name" "$tmux_window_name" "Press y to continue the script, press n to quit."

    if [ 0 = "$?" ]; then
        return 0
    fi

    log_msg_machine "$machine" "User allowed script to continue"

    return 1
}

secure_machine() {
    machine="$1"           # IP or domain
    tmux_wait_channel="$2" # Channel to wait on for scripts to complete
    tmux_inventory_channel="$3" # Channel to wait on for scripts to complete

    tmux_window_name="$(printf "%s" "$machine" | sed 's/\./_/g')"

    # Create tmux window with the machine's IP address as the name
    tmux new-window -t "$tmux_session_name" -n "$tmux_window_name";
    sleep 1

    # Add local user to machine
    log_msg_machine "$machine" "Adding new user to machine"
    tmux send-keys -t "$tmux_session_name:$tmux_window_name" "expect scripts/initial_access.exp \"$tmux_session_name:$tmux_window_name\" \"$tmux_wait_channel\" \"$machine\" \"$username\" \"$password\" \"$new_username\" \"$new_password\" \"$ssh_key_path\"; echo \$?" Enter
    tmux wait-for "$tmux_wait_channel"

    results="$(tmux capture-pane -p -t "$tmux_session_name:$tmux_window_name" | grep "." | tail -n3 | head -n2)"
    result_user_added="$(echo "$results" | tail -n1)"
    result_machine_hostname="$(echo "$results" | head -n1)"

    # Only continue if user added successfully
    if [ 0 = "$result_user_added" ]; then
        # Log out of original user and into new user
        tmux send-keys -t "$tmux_session_name:$tmux_window_name" "exit" Enter
        sleep 1
        tmux send-keys -t "$tmux_session_name:$tmux_window_name" "exit" Enter
        sleep 1
    else
        log_msg_machine "$machine" "Failed to add new user"
        manual_fix "$tmux_session_name:$tmux_window_name" "$tmux_wait_channel" "$tmux_session_name" "$tmux_window_name" "$machine" "scripts/initial_access.exp" \
            || exit 1

        result_machine_hostname="$(prompt_user "$tmux_session_name:$tmux_window_name" "$tmux_wait_channel" "$tmux_session_name" "$tmux_window_name" "$machine" "Prompting user for machine hostname" "Enter machine hostname")"
    fi

    log_msg_machine "$machine" "Added $new_username to $result_machine_hostname"
    log_msg_machine "$machine" "Hostname is $result_machine_hostname"

    if [ "unknown" != "$result_machine_hostname" ]; then
        new_tmux_window_name="$(printf "%s" "$result_machine_hostname" | sed 's/\./_/g')"
        tmux rename-window -t "$tmux_session_name:$tmux_window_name" "$new_tmux_window_name"
        tmux_window_name="$new_tmux_window_name"
        ssh_hname="$result_machine_hostname"
    else
        ssh_hname="$(printf "%s" "$result_machine_hostname" | sed 's/\./_/g')"
    fi

    tmux send-keys -t "$tmux_session_name:$tmux_window_name" "ssh \"$ssh_hname\"" Enter

    # Create new window for actions as the new user
    tmux_pane_target="$(tmux split-window -h -t "$tmux_session_name:$tmux_window_name" -P -F "#{session_name}:#{window_name}.#{pane_index}")"
    sleep 1

    machine_script_run "$tmux_pane_target" "$tmux_wait_channel" "$machine" "Testing ssh as $new_username" \
        "sh ./scripts/test_ssh.sh" "$tmux_wait_channel" "$ssh_hname" "$new_username"

    if [ 0 != "$?" ]; then
        log_msg_machine "$machine" "Unable to sign in as $new_username, or user is not a sudoer"
        manual_fix "$tmux_session_name:$tmux_window_name" "$tmux_wait_channel" "$tmux_session_name" "$tmux_window_name" "$machine" "scripts/test_ssh.sh" \
            || exit 1
    fi

    # --------------------------------------------------------------------------
    # Take snapshot
    snapshot_machine "$tmux_pane_target" "$tmux_wait_channel" "$machine" "Added admin user $new_username" \
        || exit 1
    # --------------------------------------------------------------------------

    # Get inventory information about the machine
    machine_script_run "$tmux_pane_target" "$tmux_wait_channel" "$machine" "Taking inventory" \
        "sh ./scripts/inventory.sh" "$tmux_wait_channel" "$machine" "$ssh_hname" "$dir_inventory"

    if [ 0 != "$?" ]; then
        log_msg_machine "$machine" "Failed to take inventory"
        manual_fix "$tmux_session_name:$tmux_window_name" "$tmux_wait_channel" "$tmux_session_name" "$tmux_window_name" "$machine" "scripts/inventory.sh" \
            || exit 1
    fi
    tmux wait-for -S "$tmux_inventory_channel"

    # Back up configuration files locally
    machine_script_run "$tmux_pane_target" "$tmux_wait_channel" "$machine" "Backing up config files" \
        "sh ./scripts/backup_config.sh" "$tmux_wait_channel" "$machine" "$ssh_hname" "$new_username" "$dir_backup"

    if [ 0 != "$?" ]; then
        log_msg_machine "$machine" "Failed to backup config files"
        manual_fix "$tmux_session_name:$tmux_window_name" "$tmux_wait_channel" "$tmux_session_name" "$tmux_window_name" "$machine" "scripts/backup_config.sh" \
            || exit 1
    fi

    # Install firewall packages if not present
    machine_script_run "$tmux_pane_target" "$tmux_wait_channel" "$machine" "Installing packages" \
        "sh ./scripts/package_install.sh" "$tmux_wait_channel" "$ssh_hname"

    if [ 0 != "$?" ]; then
        log_msg_machine "$machine" "Failed to install firewall packages"
        manual_fix "$tmux_session_name:$tmux_window_name" "$tmux_wait_channel" "$tmux_session_name" "$tmux_window_name" "$machine" "scripts/package_install.sh" \
            || exit 1
    fi

    # Apply host firewall rules
    machine_script_run "$tmux_pane_target" "$tmux_wait_channel" "$machine" "Applying firewall rules" \
        "sh ./scripts/firewall_incoming.sh" "$tmux_wait_channel" "$ssh_hname" "$machine_list" "$blueteam_ip_list"

    if [ 0 != "$?" ]; then
        log_msg_machine "$machine" "Failed to apply new firewall rules"
        manual_fix "$tmux_session_name:$tmux_window_name" "$tmux_wait_channel" "$tmux_session_name" "$tmux_window_name" "$machine" "scripts/firewall_incoming.sh" \
            || exit 1
    fi

    # --------------------------------------------------------------------------
    # Take snapshot
    snapshot_machine "$tmux_pane_target" "$tmux_wait_channel" "$machine" "Added permissive firewall rules" \
        || exit 1
    # --------------------------------------------------------------------------

    # Apply mode & permissions hardening
    machine_script_run "$tmux_pane_target" "$tmux_wait_channel" "$machine" "Applying mode & permissions hardening" \
        "sh ./scripts/set_permissions.sh" "$tmux_wait_channel" "$ssh_hname"

    if [ 0 != "$?" ]; then
        log_msg_machine "$machine" "Failed to set mode & permissions"
        manual_fix "$tmux_session_name:$tmux_window_name" "$tmux_wait_channel" "$tmux_session_name" "$tmux_window_name" "$machine" "scripts/set_permissions.sh" \
            || exit 1
    fi

    # --------------------------------------------------------------------------
    # Take snapshot
    snapshot_machine "$tmux_pane_target" "$tmux_wait_channel" "$machine" "Basic permissions hardening" \
        || exit 1
    # --------------------------------------------------------------------------

    # Update packages
    machine_script_run "$tmux_pane_target" "$tmux_wait_channel" "$machine" "Updating packages" \
        "sh ./scripts/package_update.sh" "$tmux_wait_channel" "$ssh_hname"

    if [ 0 != "$?" ]; then
        log_msg_machine "$machine" "Failed to update packages"
        manual_fix "$tmux_session_name:$tmux_window_name" "$tmux_wait_channel" "$tmux_session_name" "$tmux_window_name" "$machine" "scripts/package_update.sh" \
            || exit 1
    fi

    # --------------------------------------------------------------------------
    # Take snapshot
    snapshot_machine "$tmux_pane_target" "$tmux_wait_channel" "$machine" "Updated packages" \
        || exit 1
    # --------------------------------------------------------------------------

    machine_service_check "$tmux_pane_target" "$tmux_wait_channel" "$tmux_session_name" "$tmux_window_name" "$machine" "$ssh_hname" \
        || manual_fix "$tmux_session_name:$tmux_window_name" "$tmux_wait_channel" "$tmux_session_name" "$tmux_window_name" "$machine" "Service checks" \
            || exit 1

    # Reset all local user passwords
    machine_script_run "$tmux_pane_target" "$tmux_wait_channel" "$machine" "Randomizing local user passwords" \
        "sh ./scripts/pw_change_local.sh" "$tmux_wait_channel" "$tmux_pane_target" "$tmux_window_name" "$ssh_hname" "$new_username blackteam"

    passwords_changed="$?"
    if [ 0 != "$passwords_changed" ]; then
        log_msg_machine "$machine" "Local user passwords not changed"
    fi

    # --------------------------------------------------------------------------
    # Take snapshot unless passwords were not changed
    if [ 0 = "$passwords_changed" ]; then
        snapshot_machine "$tmux_pane_target" "$tmux_wait_channel" "$machine" "Reset local user passwords" \
            || exit 1
    fi
    # --------------------------------------------------------------------------

    machine_service_check "$tmux_pane_target" "$tmux_wait_channel" "$tmux_session_name" "$tmux_window_name" "$machine" "$ssh_hname" \
        || manual_fix "$tmux_session_name:$tmux_window_name" "$tmux_wait_channel" "$tmux_session_name" "$tmux_window_name" "$machine" "Service checks" \
            || exit 1

    # Install fail2ban
    machine_script_run "$tmux_pane_target" "$tmux_wait_channel" "$machine" "Installing fail2ban" \
        "sh ./scripts/package_install_fail2ban.sh" "$tmux_wait_channel" "$ssh_hname"

    fail2ban_installed="$?"
    if [ "$fail2ban_installed" != "$?" ]; then
        log_msg_machine "$machine" "Failed to install fail2ban"
        manual_fix "$tmux_session_name:$tmux_window_name" "$tmux_wait_channel" "$tmux_session_name" "$tmux_window_name" "$machine" "scripts/package_install_fail2ban.sh" \
            || exit 1
    fi

    # --------------------------------------------------------------------------
    if [ 0 = "$fail2ban_installed" ]; then
        snapshot_machine "$tmux_pane_target" "$tmux_wait_channel" "$machine" "Installed fail2ban" \
            || exit 1
    fi
    # --------------------------------------------------------------------------

    # List info about this machine
    tmux send-keys -t "$tmux_pane_target" "cat \"$dir_inventory/$machine\"" Enter;

    # Prompt user to disable unnecessary services
    machine_script_run "$tmux_pane_target" "$tmux_wait_channel" "$machine" "Prompting user to disable unnecessary services" \
        "sh ./scripts/prompt_user_yn.sh" "$tmux_wait_channel" "$tmux_session_name" "$tmux_window_name" \
        "Use the pane on the left to disable any services that aren't needed. Note that other services may depend on some of these." \
        || exit 1

    # --------------------------------------------------------------------------
    snapshot_machine "$tmux_pane_target" "$tmux_wait_channel" "$machine" "Manually disabled unnecessary services" \
        || exit 1
    # --------------------------------------------------------------------------

    # Prompt user to check for sudo misconfigurations
    machine_script_run "$tmux_pane_target" "$tmux_wait_channel" "$machine" "Prompting user to check sudo rules" \
        "sh ./scripts/prompt_user_yn.sh" "$tmux_wait_channel" "$tmux_session_name" "$tmux_window_name" \
        "Use the pane on the left to check for any sudo or doas misconfigurations. Files are /etc/sudoers, /etc/doas.conf, and /etc/doas.d . Watch for @include or @includedir directives and check those places too. Remember to check group membership in /etc/group" \
        || exit 1

    # Prompt user to check for ssh misconfigurations
    machine_script_run "$tmux_pane_target" "$tmux_wait_channel" "$machine" "Prompting user to check sshd config" \
        "sh ./scripts/prompt_user_yn.sh" "$tmux_wait_channel" "$tmux_session_name" "$tmux_window_name" \
        "Use the pane on the left to check for any sshd misconfigurations. The file is /etc/ssh/sshd_config . Watch for Include keywords and check those places too." \
        || exit 1

    # --------------------------------------------------------------------------
    # Take snapshot
    snapshot_machine "$tmux_pane_target" "$tmux_wait_channel" "$machine" "Manual edits to sudo and sshd configuration" \
        || exit 1
    # --------------------------------------------------------------------------

    # List cron jobs
    machine_script_run "$tmux_pane_target" "$tmux_wait_channel" "$machine" "Listing cron jobs" \
        "sh ./scripts/list_cron.sh" "$tmux_wait_channel" "$ssh_hname"

    if [ 0 != "$?" ]; then
        log_msg_machine "$machine" "Failed to list cron jobs"
        manual_fix "$tmux_session_name:$tmux_window_name" "$tmux_wait_channel" "$tmux_session_name" "$tmux_window_name" "$machine" "scripts/list_cron.sh" \
            || exit 1
    fi

    # Prompt user to review cron jobs
    machine_script_run "$tmux_pane_target" "$tmux_wait_channel" "$machine" "Prompting user to review cron jobs" \
        "sh ./scripts/prompt_user_yn.sh" "$tmux_wait_channel" "$tmux_session_name" "$tmux_window_name" \
        "Review the above cron jobs. Use the pane on the left to make any changes if needed." \
        || exit 1

    # --------------------------------------------------------------------------
    snapshot_machine "$tmux_pane_target" "$tmux_wait_channel" "$machine" "Manually reviewed cron jobs" \
        || exit 1
    # --------------------------------------------------------------------------

    machine_script_run "$tmux_pane_target" "$tmux_wait_channel" "$machine" "Listing suid and sgid binaries" \
        "sh ./scripts/list_suid_sgid.sh" "$tmux_wait_channel" "$ssh_hname"

    if [ 0 != "$?" ]; then
        log_msg_machine "$machine" "Failed to list suid and sgid binaries"
        manual_fix "$tmux_session_name:$tmux_window_name" "$tmux_wait_channel" "$tmux_session_name" "$tmux_window_name" "$machine" "scripts/list_suid_sgid.sh" \
            || exit 1
    fi

    machine_script_run "$tmux_pane_target" "$tmux_wait_channel" "$machine" "Prompting user to review suid and sgid binaries" \
        "sh ./scripts/prompt_user_yn.sh" "$tmux_wait_channel" "$tmux_session_name" "$tmux_window_name" \
        "Review the above suid and sgid binaries. Use the pane on the left to make any changes if needed." \
        || exit 1

    # --------------------------------------------------------------------------
    snapshot_machine "$tmux_pane_target" "$tmux_wait_channel" "$machine" "Manually reviewed cron jobs" \
        || exit 1
    # --------------------------------------------------------------------------

    # List modified packages
    machine_script_run "$tmux_pane_target" "$tmux_wait_channel" "$machine" "Listing modified packages" \
        "sh ./scripts/list_package_integrity.sh" "$tmux_wait_channel" "$ssh_hname"

    if [ 0 != "$?" ]; then
        log_msg_machine "$machine" "Failed to list modified packages"
        manual_fix "$tmux_session_name:$tmux_window_name" "$tmux_wait_channel" "$tmux_session_name" "$tmux_window_name" "$machine" "scripts/list_package_integrity.sh" \
            || exit 1
    fi

    # Prompt user to review modified packages
    machine_script_run "$tmux_pane_target" "$tmux_wait_channel" "$machine" "Prompting user to view modified packages" \
        "sh ./scripts/prompt_user_yn.sh" "$tmux_wait_channel" "$tmux_session_name" "$tmux_window_name" \
        "Review the above modified packages. Use the pane on the left to make any changes if needed." \
        || exit 1

    # --------------------------------------------------------------------------
    snapshot_machine "$tmux_pane_target" "$tmux_wait_channel" "$machine" "Manually reviewed modified packages" \
        || exit 1
    # --------------------------------------------------------------------------

    # List info about this machine
    tmux send-keys -t "$tmux_pane_target" "cat \"$dir_inventory/$machine\"" Enter;

    # Apply sandbox to services
    machine_script_run "$tmux_pane_target" "$tmux_wait_channel" "$machine" "Prompting user to sandbox services" \
        "sh ./scripts/sandbox.sh" "$tmux_wait_channel" "$tmux_session_name" "$tmux_window_name" "$machine" "$ssh_hname" "$dir_sandbox"

    # --------------------------------------------------------------------------
    snapshot_machine "$tmux_pane_target" "$tmux_wait_channel" "$machine" "Manually sandboxed services" \
        || exit 1
    # --------------------------------------------------------------------------

    # Create outbound firewall rules based on traffic
    machine_script_run "$tmux_pane_target" "$tmux_wait_channel" "$machine" "Adding outbound firewall rules" \
        "sh ./scripts/firewall_outgoing.sh" "$tmux_wait_channel" "$tmux_pane_target" "$tmux_window_name" "$machine" "$ssh_hname" "$fw_wait" "$dir_hosts"

    rules_added="$?"
    if [ 0 != "$rules_added" ]; then
        log_msg_machine "$machine" "Outbound firewall rules not added"
    fi

    # --------------------------------------------------------------------------
    # Take snapshot unless firewall rules were not changed
    if [ 0 = "$rules_added" ]; then
        snapshot_machine "$tmux_pane_target" "$tmux_wait_channel" "$machine" "Added outbound firewall rules" \
            || exit 1
    fi
    # --------------------------------------------------------------------------

    # Interactive session
    tmux send-keys -t "$tmux_pane_target" "ssh \"$ssh_hname\"" Enter;
}

# Take initial snapshots of all machines
if [ 1 = "$take_snapshots" ]; then
    tmux new-window -t "$tmux_session_name" -n "initial-snapshots";
    sleep 1
    snapshot_machine "$tmux_session_name:initial-snapshots" "10" "*" "Initial snapshot" \
        || exit 1
fi

# Start network scan
tmux new-window -t "$tmux_session_name" -n "network-scan";
sleep 1
mkdir -p "$dir_nmap"
tmux send-keys -t "$tmux_session_name:network-scan" "nmap --min-rate=1000 --max-hostgroup 64 -oA \"$dir_nmap/network-scan\" $network_list" Enter

# Run hardening on all machines
counter=1
for machine in $machine_list; do
    secure_machine "$machine" $((200 + counter)) $((500 + counter)) &
    counter=$((counter + 1))
done

for i in $(seq 1 $counter); do
    tmux wait-for $((500 + i))

    # List inventory information about all machines
    tmux new-window -t "$tmux_session_name" -n "inventory";
    sleep 1
    tmux send-keys -t "$tmux_session_name:inventory" "cat \"$dir_inventory\"/*" Enter;
done

wait
