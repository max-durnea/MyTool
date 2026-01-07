import requests
import dns.resolver
import itertools
from colorama import Fore, Style
from concurrent.futures import ThreadPoolExecutor

# Default wordlist names
DEFAULT_DIR_LIST = "common_dirs.txt"
DEFAULT_SUB_LIST = "subdomains.txt"

def request_url(url, counter, limit):
    """Helper for multithreaded directory scanning with atomic limit check"""
    # Increment counter and check if we've passed the limit
    if next(counter) > limit:
        return

    try:
        headers = {'User-Agent': 'Mozilla/5.0 (CTF Automation Tool)'}
        response = requests.get(url, headers=headers, timeout=3, allow_redirects=False)
        
        if response.status_code == 200:
            print(f"  {Fore.GREEN}[+] Found: {url} (200 OK)")
        elif response.status_code in [301, 302]:
            print(f"  {Fore.YELLOW}[+] Redirect: {url} ({response.status_code}) -> {response.headers.get('Location', '')}")
    except requests.RequestException:
        pass

def directory_discovery(target, wordlist_path=None, limit=2000):
    path = wordlist_path if wordlist_path else DEFAULT_DIR_LIST
    print(f"\n{Fore.CYAN}[*] Starting Directory Discovery on {target} (Limit: {limit})...")
    
    url_base = f"http://{target}" if not target.startswith("http") else target
    # Atomic counter starting at 1
    counter = itertools.count(1)

    try:
        with open(path, 'r') as f:
            # Generator to feed threads line-by-line
            url_generator = (f"{url_base}/{line.strip().lstrip('/')}" for line in f if line.strip())
            
            with ThreadPoolExecutor(max_workers=20) as executor:
                # Pass counter and limit to each thread
                for url in url_generator:
                    executor.submit(request_url, url, counter, limit)
                    
    except FileNotFoundError:
        print(f"{Fore.RED}[X] Error: {path} not found. Skipping directory discovery.")

def subdomain_discovery(domain, wordlist_path=None, limit=2000):
    path = wordlist_path if wordlist_path else DEFAULT_SUB_LIST
    print(f"\n{Fore.CYAN}[*] Starting Subdomain Discovery on {domain} (Limit: {limit})...")
    
    count = 0
    try:
        with open(path, 'r') as f:
            for line in f:
                if count >= limit:
                    break
                
                sub = line.strip()
                if not sub:
                    continue
                    
                target_sub = f"{sub}.{domain}"
                try:
                    dns.resolver.resolve(target_sub, 'A')
                    print(f"  {Fore.GREEN}[+] Found Subdomain: {target_sub}")
                    count += 1
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, Exception):
                    count += 1
                    continue
    except FileNotFoundError:
        print(f"{Fore.RED}[X] Error: {path} not found. Skipping subdomain discovery.")