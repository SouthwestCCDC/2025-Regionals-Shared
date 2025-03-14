#!/bin/bash

# Script to run nmap and extract reachable IPs

# Check if a subnet was provided
if [ -z "$1" ]; then
    echo "Usage: $0 <subnet>"
    echo "Example: $0 192.168.1.0/24"
    exit 1
fi

# Subnet to scan
SUBNET=$1

# Run nmap and extract IPs
echo "Scanning subnet: $SUBNET"
nmap -sn $SUBNET | awk '/Nmap scan report/{print $NF}' | tr -d '()' > inventory

# Display the results
echo "Reachable IP addresses:"
cat inventory

