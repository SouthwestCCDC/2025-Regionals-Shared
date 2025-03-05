``` python
#!/usr/bin/env python3
import subprocess
import xml.etree.ElementTree as ET
import json
import os
import re
import datetime
import sys
import time
import ipaddress  

def sanitize_subnet(subnet):
    return subnet.replace("/", "_")

def scan_online_hosts(network):
    command = ["nmap", "-sn", "-oX", "-", network]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        print("Error running nmap -sn scan:", e)
        return []
    online_hosts = []
    try:
        root = ET.fromstring(result.stdout)
        for host in root.findall('host'):
            status = host.find('status')
            if status is not None and status.get('state') == 'up':
                addr = host.find('address')
                if addr is not None:
                    ip = addr.get('addr')
                    online_hosts.append(ip)
    except Exception as e:
        print("Error parsing nmap XML output for online hosts:", e)
    return online_hosts

def run_nmap_scan(host, args, timeout=60):
    command = ["nmap"] + args + ["-oX", "-", host]
    print("Running command: " + " ".join(command))
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=True)
        return result.stdout
    except subprocess.TimeoutExpired:
        print(f"Scan for {host} with args {args} timed out after {timeout} seconds. Skipping scan.")
        return ""
    except subprocess.CalledProcessError as e:
        print(f"Error running nmap scan on {host} with args {args}: {e}")
        return ""

def parse_nmap_ports(xml_data):
    if not xml_data.strip():
        return []
    
    ports = []
    try:
        root = ET.fromstring(xml_data)
        for host in root.findall('host'):
            status = host.find('status')
            if status is not None and status.get('state') != 'up':
                continue
            ports_elem = host.find('ports')
            if ports_elem is not None:
                for port in ports_elem.findall('port'):
                    state_elem = port.find('state')
                    if state_elem is not None and state_elem.get('state') == 'open':
                        ports.append(port.get('portid'))
    except Exception as e:
        print("Error parsing port XML data:", e)
    return ports

def perform_scans(host):
    scans = {}
    print(f"\nScanning host: {host}")
    xml_tcp = run_nmap_scan(host, ["-sT", "-T4"])
    scans["tcp"] = parse_nmap_ports(xml_tcp)
    xml_udp = run_nmap_scan(host, ["-sU", "--top-ports", "1000", "-T4"])
    scans["udp"] = parse_nmap_ports(xml_udp)
    return scans

def compare_results(previous, current):
    changes = []
    prev_hosts = set(previous.keys())
    curr_hosts = set(current.keys())
    for host in prev_hosts - curr_hosts:
        changes.append(f"Host {host} went offline.")
    for host in curr_hosts - prev_hosts:
        changes.append(f"Host {host} is now online.")
    for host in prev_hosts & curr_hosts:
        for scan_type in ["tcp", "udp"]:
            prev_ports = set(previous[host].get(scan_type, []))
            curr_ports = set(current[host].get(scan_type, []))
            new_ports = curr_ports - prev_ports
            missing_ports = prev_ports - curr_ports
            if new_ports:
                changes.append(f"Host {host} ({scan_type}): New open ports: {sorted(new_ports)}")
            if missing_ports:
                changes.append(f"Host {host} ({scan_type}): Ports now closed: {sorted(missing_ports)}")
    return changes

def main():
    ip_input = input("Enter one or more IPv4 addresses (optionally with '-<prefix>') separated by commas: ").strip()
    if not ip_input:
        print("No IP addresses provided.")
        sys.exit(1)
    ips = [item.strip() for item in ip_input.split(",") if item.strip()]
    subnets = []
    for entry in ips:
        if '-' in entry:
            parts = re.split(r"\s*-\s*", entry)
            if len(parts) != 2:
                print(f"Invalid input format: {entry}")
                sys.exit(1)
            ip_addr = parts[0]
            try:
                prefix = int(parts[1])
            except ValueError:
                print(f"Invalid prefix value: {parts[1]}")
                sys.exit(1)
            if prefix < 0 or prefix > 32:
                print("Invalid prefix for IPv4. Must be between 0 and 32.")
                sys.exit(1)
        else:
            ip_addr = entry
            prefix = 24
        if not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip_addr):
            print(f"Invalid IPv4 address format: {ip_addr}")
            sys.exit(1)
        try:
            network_obj = ipaddress.ip_network(f"{ip_addr}/{prefix}", strict=False)
        except ValueError as ve:
            print(f"Error calculating network for {ip_addr}/{prefix}: {ve}")
            sys.exit(1)
        network = str(network_obj)
        subnets.append(network)
    print("Scanning the following subnets:")
    for subnet in subnets:
        print("  " + subnet)
    last_host_scan = 0    
    last_full_scan = 0    
    print("Starting scheduled scans. Press Ctrl+C to exit.")
    while True:
        now = time.time()
        if now - last_host_scan >= 10 * 60:
            for subnet in subnets:
                print(f"\n--- Running Host Discovery Scan for subnet: {subnet} ---")
                host_list = scan_online_hosts(subnet)
                host_prev_file = f"host_previous_{sanitize_subnet(subnet)}.json"
                if os.path.exists(host_prev_file):
                    try:
                        with open(host_prev_file, "r") as f:
                            prev_hosts = json.load(f)
                    except Exception as e:
                        print(f"Error loading previous host list for {subnet}. Starting fresh. Error: {e}")
                        prev_hosts = []
                else:
                    prev_hosts = []
                prev_set = set(prev_hosts)
                curr_set = set(host_list)
                host_changes = []
                for host in curr_set - prev_set:
                    host_changes.append(f"Host {host} came online in subnet {subnet}.")
                for host in prev_set - curr_set:
                    host_changes.append(f"Host {host} went offline in subnet {subnet}.")
                if host_changes:
                    timestamp = datetime.datetime.now().isoformat()
                    with open("host_changes.txt", "a") as f:
                        f.write(f"=== Host Scan for subnet {subnet} performed on {timestamp} ===\n")
                        for change in host_changes:
                            f.write(change + "\n")
                        f.write("\n")
                    print(f"Host changes detected in subnet {subnet} and logged:")
                    for change in host_changes:
                        print(" -", change)
                else:
                    print(f"No host changes detected in subnet {subnet}.")
                try:
                    with open(host_prev_file, "w") as f:
                        json.dump(host_list, f, indent=4)
                except Exception as e:
                    print(f"Error saving current host list for subnet {subnet}: {e}")
            last_host_scan = now
        if now - last_full_scan >= 60 * 60:
            for subnet in subnets:
                print(f"\n--- Running Full TCP/UDP Scan for subnet: {subnet} ---")
                online_hosts = scan_online_hosts(subnet)
                if online_hosts:
                    current_results = {}
                    for host in online_hosts:
                        current_results[host] = perform_scans(host)
                    full_prev_file = f"previous_scan_{sanitize_subnet(subnet)}.json"
                    if os.path.exists(full_prev_file):
                        try:
                            with open(full_prev_file, "r") as f:
                                previous_results = json.load(f)
                        except Exception as e:
                            print(f"Error loading previous full scan results for subnet {subnet}. Starting fresh. Error: {e}")
                            previous_results = {}
                    else:
                        previous_results = {}
                    changes = compare_results(previous_results, current_results)
                    if changes:
                        timestamp = datetime.datetime.now().isoformat()
                        with open("changes.txt", "a") as f:
                            f.write(f"=== Full Scan for subnet {subnet} performed on {timestamp} ===\n")
                            for change in changes:
                                f.write(change + "\n")
                            f.write("\n")
                        print(f"Changes detected in full scan for subnet {subnet} and documented in changes.txt:")
                        for change in changes:
                            print(" -", change)
                    else:
                        print(f"No changes detected in full scan for subnet {subnet}.")
                    try:
                        with open(full_prev_file, "w") as f:
                            json.dump(current_results, f, indent=4)
                    except Exception as e:
                        print(f"Error saving full scan results for subnet {subnet}: {e}")
                else:
                    print(f"No online hosts discovered during full scan for subnet {subnet}.")
            last_full_scan = now
        time.sleep(10)
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScript terminted by user.")
```

