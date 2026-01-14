import nmap
import socket

def get_local_ip():
    try:
        # Create a socket object to get the local IP address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Connect to a public IP address (Google's DNS server)
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        print("Error while getting local IP:", e)
        return None

def scan_subnet(subnet):
    local_ip = get_local_ip()
    exclude_endings = ['.1', '.2', '.255']
    nm = nmap.PortScanner()
    nm.scan(hosts=subnet, arguments='-sn')
    alive_hosts = [x for x in nm.all_hosts() if nm[x]['status']['state'] == 'up' and not any(x.endswith(end) for end in exclude_endings) and x != local_ip]
    return alive_hosts

def is_host_alive(ip):
    nm = nmap.PortScanner()
    # We specify a TCP SYN ping scan to check if the host is alive
    response = nm.scan(hosts=ip, arguments='-sn')
    return ip in response['scan']

def scan_ip_or_subnet(input_str):
    hosts_list = []
    if '/' in input_str:
        return scan_subnet(input_str)
    else:
        if is_host_alive(input_str):
            hosts_list.append(input_str)
    return hosts_list
