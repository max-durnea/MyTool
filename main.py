
import argparse
from scan import nmap_scan

def main():
    parser = argparse.ArgumentParser(description="CTF Automation Tool - Nmap Module")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("-f", "--fast", action="store_true", help="Fast scan first, then enumerate found ports")
    
    args = parser.parse_args()
    nmap_scan(args.target, args.fast)

if __name__ == "__main__":
    main()