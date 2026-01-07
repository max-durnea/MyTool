import nmap
from colorama import Fore, Style, init

init(autoreset=True)

def print_results(scanner):
    """Helper function to print results in the desired format"""
    for host in scanner.all_hosts():
        print(f"\nHost: {host}")
        for proto in scanner[host].all_protocols():
            print(f"Protocol: {Fore.YELLOW}{proto.upper()}")
            ports = sorted(scanner[host][proto].keys())
            for port in ports:
                port_data = scanner[host][proto][port]
                state = port_data['state']
                service = port_data['name']
                product = port_data.get('product', '')
                version = port_data.get('version', '')
                extrainfo = port_data.get('extrainfo', '')

                state_color = Fore.GREEN if state == 'open' else Fore.RED
                print(f"  [+] Port {Fore.YELLOW}{port}{Style.RESET_ALL}: {state_color}{state}")
                print(f"      Service: {Fore.BLUE}{service}")

                if product or version:
                    description = f"{product} {version} {extrainfo}".strip()
                    print(f"      Version: {Fore.LIGHTWHITE_EX}{description}")
                
                # Check for script results (-sC)
                if 'script' in port_data:
                    for script_id, output in port_data['script'].items():
                        clean_out = output.replace('\n', '\n          ')
                        print(f"      {Fore.CYAN}|_ {script_id}: {Fore.WHITE}{clean_out}")

def nmap_scan(target, fast_mode=False):
    scanner = nmap.PortScanner()
    
    # Logic for initial scan options
    options = "-T4 -F" if fast_mode else "-sV -sC -T4"
    print(f"{Fore.CYAN}[*] Starting scan on {target} with options: {options}")

    try:
        scanner.scan(target, arguments=options)
        print_results(scanner)

        # AUTOMATIC SECOND STAGE: Only if fast_mode was true
        if fast_mode:
            open_ports = []
            for host in scanner.all_hosts():
                for proto in scanner[host].all_protocols():
                    for port in scanner[host][proto]:
                        if scanner[host][proto][port]['state'] == 'open':
                            open_ports.append(str(port))
            
            if open_ports:
                port_list = ",".join(open_ports)
                print(f"\n{Fore.CYAN}[*] Fast scan complete. Found: {port_list}")
                print(f"{Fore.CYAN}[*] Now running intensive scan (-sV -sC) on discovered ports...")
                
                scanner.scan(target, ports=port_list, arguments="-sV -sC -T4")
                print_results(scanner)
            else:
                print(f"\n{Fore.RED}[!] No open ports found to enumerate further.")

    except Exception as e:
        print(f"{Fore.RED}[X] Error during scan: {e}")

