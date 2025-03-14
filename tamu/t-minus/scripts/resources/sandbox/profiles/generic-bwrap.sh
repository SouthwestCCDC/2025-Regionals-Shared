#!/bin/sh

service_name=generic_service
service_binary=/sbin/generic_service

# Make paths read/write. Files must exist
# Bind format:
#   --bind /path/to/source /path/to/destination
#   --bind-try /path/to/maybe/existing/source /path/to/destination
#   --ro-bind /path/to/source /path/to/destination
service_binds="\
"

bwrap \
    --cap-drop ALL \
    --cap-add cap_net_bind_service \
    --cap-add cap_setuid \
    --cap-add cap_setgid \
    --cap-add cap_chown \
    --ro-bind-try /usr/lib /usr/lib \
    --ro-bind-try /usr/lib64 /usr/lib64 \
    --ro-bind-try /lib /lib \
    --ro-bind-try /lib64 /lib64 \
    --dev-bind /dev/null /dev/null \
    --dev-bind /dev/zero /dev/zero \
    --dev-bind /dev/random /dev/random \
    --tmpfs /tmp \
    --tmpfs /var/tmp \
    --tmpfs "/var/cache/$service_name" \
    --bind "/run/$service_name" "/run/$service_name" \
    --ro-bind "/var/lib/$service_name" "/var/lib/$service_name" \
    --bind "/var/log/$service_name" "/var/log/$service_name" \
    --ro-bind "/etc/$service_name" "/etc/$service_name" \
    --ro-bind "$service_binary" "$service_binary" \
    $service_binds \
    "$service_binary" "$@"
