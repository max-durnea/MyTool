import nmap
import re
from colorama import Fore, Style, init

init(autoreset=True)

def extract_domains(scanner):
    """
    Extracts unique domain names found in scan results.
    """
    found_domains = set()
    # Broad domain regex: finds things like 'sub.example.com'
    domain_pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'

    for host in scanner.all_hosts():
        # 1. Check Nmap's internal hostnames list
        for hostname_data in scanner[host].hostnames():
            name = hostname_data.get('name')
            if name and not name.endswith('.in-addr.arpa'): # Ignore reverse DNS noise
                found_domains.add(name)

        # 2. Check all script outputs (Certificates, banners, etc.)
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto]:
                port_data = scanner[host][proto][port]
                if 'script' in port_data:
                    for output in port_data['script'].values():
                        # Extract matches from the script output text
                        matches = re.findall(domain_pattern, output)
                        for m in matches:
                            # Filter out false positives like nmap.org or IP strings
                            if not m.lower().endswith('nmap.org') and not re.match(r'^\d+\.', m):
                                found_domains.add(m.lower())
    
    return found_domains

def print_results(scanner):
    # (Your existing print logic stays here)
    for host in scanner.all_hosts():
        print(f"\nHost: {host}")
        for proto in scanner[host].all_protocols():
            print(f"Protocol: {Fore.YELLOW}{proto.upper()}")
            ports = sorted(scanner[host][proto].keys())
            for port in ports:
                port_data = scanner[host][proto][port]
                state = port_data['state']
                service = port_data['name']
                
                state_color = Fore.GREEN if state == 'open' else Fore.RED
                print(f"  [+] Port {Fore.YELLOW}{port}{Style.RESET_ALL}: {state_color}{state}")
                print(f"      Service: {Fore.BLUE}{service}")

                if 'script' in port_data:
                    for script_id, output in port_data['script'].items():
                        clean_out = output.replace('\n', '\n          ')
                        print(f"      {Fore.CYAN}|_ {script_id}: {Fore.WHITE}{clean_out}")

def nmap_scan(target, fast_mode=False):
    scanner = nmap.PortScanner()
    options = "-T4 -F" if fast_mode else "-sV -sC -T4"
    print(f"{Fore.CYAN}[*] Starting scan on {target}...")

    try:
        scanner.scan(target, arguments=options)
        print_results(scanner)

        if fast_mode:
            open_ports = [str(p) for proto in scanner[target].all_protocols() for p in scanner[target][proto]]
            if open_ports:
                port_list = ",".join(open_ports)
                print(f"\n{Fore.CYAN}[*] Running intensive scan on: {port_list}")
                scanner.scan(target, ports=port_list, arguments="-sV -sC -T4")
                print_results(scanner)

        # FINAL EXTRACTION: Pull domains for the next stage
        discovered_domains = extract_domains(scanner)
        if discovered_domains:
            print(f"\n{Fore.GREEN}[+] Discovered FQDNs for enumeration: {', '.join(discovered_domains)}")
        
        return discovered_domains

    except Exception as e:
        print(f"{Fore.RED}[X] Error: {e}")
        return set()