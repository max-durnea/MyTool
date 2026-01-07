import argparse
from scan import nmap_scan
from web_discovery import directory_discovery, subdomain_discovery, DEFAULT_DIR_LIST, DEFAULT_SUB_LIST
from colorama import Fore, init

init(autoreset=True)

def main():
    parser = argparse.ArgumentParser(description="Automated CTF Recon Tool")
    
    # Target and Nmap Options
    parser.add_argument("target", help="Target IP or Domain")
    parser.add_argument("-f", "--fast", action="store_true", help="Fast Nmap scan first, then intensive scan")
    
    # Discovery Toggles
    parser.add_argument("--no-dir", action="store_true", help="Disable directory discovery")
    parser.add_argument("--no-sub", action="store_true", help="Disable subdomain discovery")
    
    # Wordlist Overrides
    parser.add_argument("-dw", "--dir-wordlist", help=f"Custom directory wordlist")
    parser.add_argument("-sw", "--sub-wordlist", help=f"Custom subdomain wordlist")

    args = parser.parse_args()

    print(f"{Fore.MAGENTA}{'='*50}\n      CTF AUTOMATION TOOL - RECON PHASE\n{'='*50}\n")

    # 1. Nmap Scan - Now returns a set of discovered domains
    discovered_domains = nmap_scan(args.target, args.fast)

    # 2. Build Target List for Discovery
    # We always include the original target. If Nmap found new domains, we add them.
    targets_to_enumerate = {args.target} | discovered_domains

    print(f"\n{Fore.CYAN}[*] Starting Discovery Phase on identified targets...")

    for t in targets_to_enumerate:
        # Check if current target 't' is a domain (contains dots and letters)
        is_domain = any(char.isalpha() for char in t) and "." in t

        # Subdomain Discovery: Only if not disabled AND target is a domain
        if not args.no_sub:
            if is_domain:
                subdomain_discovery(t, args.sub_wordlist)
            else:
                print(f"{Fore.YELLOW}[!] Skipping subdomain search for IP: {t}")

        # Directory Discovery: Only if not disabled
        if not args.no_dir:
            directory_discovery(t, args.dir_wordlist)

    print(f"\n{Fore.MAGENTA}[!] All automation stages complete.")

if __name__ == "__main__":
    main()