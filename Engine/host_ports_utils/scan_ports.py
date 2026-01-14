import nmap
import os
import socket

def ssh_port_open(target_host):
    nm = nmap.PortScanner()

    # Scan the target host for open SSH ports (port 22)
    nm.scan(target_host, '22')

    # Check if the target host has any open SSH ports
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            if proto == 'tcp':
                # Get the state and service name for each port
                for port in nm[host][proto]:
                    port_info = nm[host][proto][port]
                    port_state = port_info['state']
                    service_name = port_info['name']

                    # Check if the port is open and service is SSH-related
                    if port_state == 'open' and 'ssh' in service_name.lower():
                        return True

    # If no open SSH ports were found, return False
    return False

def http_port_open(target_host):
    # Define the list of ports to scan for HTTP services
    http_ports = [80, 443, 8008, 8080, 8088]

    nm = nmap.PortScanner()

    # Scan the target host for the specified ports
    ports_to_scan = ','.join(str(port) for port in http_ports)
    nm.scan(target_host, ports_to_scan)

    # Check if any of the specified ports have an open HTTP service
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            if proto == 'tcp':
                for port in nm[host][proto]:
                    port_info = nm[host][proto][port]
                    port_state = port_info['state']
                    service_name = port_info['name']

                    if port_state == 'open' and 'http' in service_name.lower():
                        return True

    # If no open HTTP ports are found, return False
    return False

#--- check if scanning port
file_path = os.path.join(os.path.dirname(__file__), '../engine.conf')

def scanning_port22():
    try:
        with open(file_path, 'r') as file:
            for line in file:
                # Remove leading and trailing whitespaces
                line = line.strip()

                # Ignore empty lines
                if not line:
                    continue

                # Check if the line starts with "[ssh-port22]"
                if line.startswith('[ssh-port22]'):
                    # Check if the line is not commented
                    return not line.startswith('#')

        # If [ssh-port22] is not found, return False
        return False
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
        return False
    
def scanning_port80():
    try:
        with open(file_path, 'r') as file:
            for line in file:
                # Remove leading and trailing whitespaces
                line = line.strip()

                # Ignore empty lines
                if not line:
                    continue

                # Check if the line starts with "[http_dvwa-port80]"
                if line.startswith('[http_dvwa-port80]'):
                    # Check if the line is not commented
                    return not line.startswith('#')

        # If [ssh-port22] is not found, return False
        return False
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
        return False

def port_conf(ip_address):
    scanning_ports =[]
    if scanning_port22():
        if ssh_port_open(ip_address):
            scanning_ports.append(22)
        else:
            print('closed port22')
            return 'error'
    
    if scanning_port80():
        if http_port_open(ip_address):
            scanning_ports.append(80)
        else:
            return 'error'
    return scanning_ports
        
def get_port_range_socket(target_host):
    open_ports = []
    
    for port in range(1, 65536):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Adjust the timeout as needed
        
        result = sock.connect_ex((target_host, port))
        if result == 0:
            open_ports.append(port)
        
        sock.close()
    
    if open_ports:
        min_port = min(open_ports)
        max_port = max(open_ports)
        return min_port, max_port
    else:
        return None


def validate_port_range(min_port, max_port):
    if min_port < 1 or max_port > 65535:
        print("Invalid port list. Ports must be in the range [1-65535]. Scan terminated")
        return True
    return False

def get_port_range(ip_address):
    port_range = get_port_range_socket(ip_address)
    if port_range:
        min_port, max_port = port_range
        print("Port Range:")
        print(f"Minimum Port: {min_port}")
        print(f"Maximum Port: {max_port}")
        if validate_port_range(min_port, max_port):
            return False

    else:
        print("No open ports found.")
        return