import subprocess
import xml.etree.ElementTree as ET
from ipaddress import ip_network
import os

CRITICAL_PORTS = {
    20: "FTP Data Transfer",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    137: "NetBIOS Name Service",
    139: "NetBIOS Session Service",
    443: "HTTPS",
    445: "SMB",
    1433: "Microsoft SQL Server",
    1434: "Microsoft SQL Server Browser",
    3306: "MySQL",
    3389: "Remote Desktop Protocol",
    8080: "HTTP Alternate",
    8443: "HTTPS Alternate"
}

PORT_INFO = {
    (20, 21): "FTP ports are known for being outdated and insecure. Vulnerable to brute-force attacks, anonymous authentication, XSS, and directory traversal.",
    22: "SSH port. Can be exploited using leaked SSH keys or brute-force attacks.",
    23: "Telnet is outdated and insecure. Vulnerable to credential brute-forcing, spoofing, and sniffing.",
    25: "SMTP port. Vulnerable to spoofing and spamming if not properly configured.",
    53: "DNS port. Particularly vulnerable to DDoS attacks.",
    (137, 139, 445): "NetBIOS and SMB ports. Vulnerable to EternalBlue exploit, NTLM hash capturing, and brute-force attacks.",
    (80, 443, 8080, 8443): "HTTP/HTTPS ports. Vulnerable to XSS, SQL injections, CSRF, and DDoS attacks.",
    (1433, 1434, 3306): "Database ports. Often probed for unprotected databases with exploitable default configurations.",
    3389: "Remote Desktop port. Vulnerable to various RDP vulnerabilities and weak authentication attacks."
}

def run_nmap_scan(target, output_file, scan_type='detailed'):
    try:
        if scan_type == 'detailed':
            command = f"nmap -T4 --host-timeout 5m -oX {output_file} {target}"
        elif scan_type == 'ping':
            command = f"nmap -sn -oX {output_file} {target}"

        print(f"Running command: {command}")
        result = subprocess.run(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            print(f"Error running Nmap: {result.stderr}")
            return None
        return output_file
    except Exception as e:
        print(f"Exception during Nmap scan: {e}")
        return None

def parse_nmap_results(xml_file):
    vulnerabilities = []
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        for host in root.findall('host'):
            ip = host.find('address').get('addr')
            ports = host.find('ports')
            if ports is not None:
                for port in ports.findall('port'):
                    state = port.find('state').get('state')
                    if state == 'open':
                        protocol = port.get('protocol')
                        portid = int(port.get('portid'))
                        service_info = port.find('service')
                        service = service_info.get('name') if service_info is not None else 'unknown'
                        product = service_info.get('product') if service_info is not None else 'unknown'
                        version = service_info.get('version') if service_info is not None else 'unknown'
                        
                        vuln = {
                            'ip': ip,
                            'port': portid,
                            'protocol': protocol,
                            'service': service,
                            'product': product,
                            'version': version,
                            'criticality': 'High' if portid in CRITICAL_PORTS else 'Low'
                        }
                        
                        for port_range, info in PORT_INFO.items():
                            if isinstance(port_range, tuple) and portid in port_range:
                                vuln['info'] = info
                                break
                            elif portid == port_range:
                                vuln['info'] = info
                                break
                        
                        vulnerabilities.append(vuln)
    except ET.ParseError as e:
        print(f"Error parsing Nmap XML output: {e}")
    except Exception as e:
        print(f"Exception during Nmap result parsing: {e}")
    return vulnerabilities

def get_local_ip_range():
    try:
        result = subprocess.run(["ip", "route"], stdout=subprocess.PIPE, text=True)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if 'src' in line:
                    parts = line.split()
                    subnet = parts[0]
                    if '/' in subnet:
                        print(f"Detected local IP range: {subnet}")
                        return subnet
        print("Failed to detect local IP range; defaulting to 127.0.0.1.")
        return "127.0.0.1"
    except Exception as e:
        print(f"Exception getting local IP range: {e}")
    return "127.0.0.1"

def run_host_scan():
    local_ip = '127.0.0.1'
    results_file = "host_scan_results.xml"
    vulnerabilities = []

    print(f"Running host scan on IP: {local_ip}")
    file = run_nmap_scan(local_ip, results_file, scan_type='detailed')
    if file:
        vulnerabilities.extend(parse_nmap_results(file))

    return vulnerabilities

def run_subnet_scan(subnet):
    vulnerabilities = []

    live_hosts_file = "live_hosts.xml"
    run_nmap_scan(subnet, live_hosts_file, scan_type='ping')

    live_hosts = parse_nmap_results(live_hosts_file)

    for host in live_hosts:
        ip_str = host['ip']
        print(f"Scanning network device: {ip_str}")
        temp_results_file = ip_str.replace('/', '_') + "_temp_scan_results.xml"
        file = run_nmap_scan(ip_str, temp_results_file, scan_type='detailed')
        if file:
            results = parse_nmap_results(file)
            vulnerabilities.extend(results)
            os.remove(temp_results_file)

    return vulnerabilities

def write_results_to_xml(vulnerabilities, xml_file):
    root = ET.Element("nmaprun")
    for vuln in vulnerabilities:
        host = ET.SubElement(root, "host")
        address = ET.SubElement(host, "address", addr=vuln['ip'])
        ports = ET.SubElement(host, "ports")
        port = ET.SubElement(ports, "port", protocol=vuln['protocol'], portid=str(vuln['port']))
        state = ET.SubElement(port, "state", state="open")
        service = ET.SubElement(port, "service", name=vuln['service'], product=vuln['product'], version=vuln['version'])

    tree = ET.ElementTree(root)
    tree.write(xml_file)

def calculate_network_security_score(vulnerabilities, target_ip):
    host_vulnerabilities = [v for v in vulnerabilities if v['ip'] == target_ip]
    total_vulnerabilities = len(host_vulnerabilities)
    critical_vulnerabilities = len([v for v in host_vulnerabilities if v['criticality'] == 'High'])

    base_score = 100
    deduction_per_critical = 10
    deduction_per_non_critical = 2

    score = base_score - (critical_vulnerabilities * deduction_per_critical) - ((total_vulnerabilities - critical_vulnerabilities) * deduction_per_non_critical)
    return max(0, min(100, score))
