import time
import ssl
import socket
import whois
import dns.resolver
import requests
import shodan
import os
import sys

# Check root permissions

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def check_root():
    if os.geteuid()!= 0:
        print(f"{Colors.FAIL}This script requires root privileges. Please run as root or use sudo.{Colors.ENDC}")
        sys.exit(1)

greeting = f"""{Colors.OKGREEN}

        _______     __________   _______ 
        __  __ \    ___  ____/   __  __ |
        _  / / /    __  /_       _  / / /
        / /_/ /     _  __/       / /_/ / 
        \____/      /_/          \____/  

         -Basic Information Collector-              

{Colors.ENDC}
"""

# Print with delay function
def print_with_delay(lines, delay=1):
    for line in lines:
        print(line)
        time.sleep(delay)
    skip = input("Press Enter to continue")


# Find IP Address by Domain Name
def get_ip(domain_name):
    try:
        ip_address = socket.gethostbyname(domain_name)
        return [f"{Colors.HEADER}IP Address of {Colors.ENDC}{domain_name} {Colors.HEADER}is {Colors.ENDC}{ip_address}"]
    except socket.gaierror:
        return [f"{Colors.FAIL}Could not resolve domain name."]
    except Exception as e:
        return f"An error occurred: {str(e)}{Colors.ENDC}"

# Whois query by domain name
def whois_query(domain_name):
    try:
        w = whois.whois(domain_name)
        lines = [
            f"{Colors.OKBLUE}Domain Name{Colors.ENDC}:  {Colors.OKGREEN}{w.domain_name}{Colors.ENDC}",
            f"{Colors.OKBLUE}Registrar:{Colors.ENDC}  {Colors.OKGREEN}{w.registrar}{Colors.ENDC}",
            f"{Colors.OKBLUE}Creation Date:{Colors.ENDC}  {Colors.OKGREEN}{w.creation_date}{Colors.ENDC}",
            f"{Colors.OKBLUE}Expiration Date:{Colors.ENDC}  {Colors.OKGREEN}{w.expiration_date}{Colors.ENDC}",
            f"{Colors.OKBLUE}Name Servers:{Colors.ENDC} {Colors.OKGREEN}{', '.join(w.name_servers)}{Colors.ENDC}"
        ]
        return lines
        
    except Exception as e:
        return [str(e)]
    
# Scan common ports for domain name
def scan_ports(domain_name, ports=[80, 443, 21, 22, 23, 25]):
    ip = socket.gethostbyname(domain_name)
    if not ip:
        return ["Not Found IP Address !!"]
    results = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            s.connect((ip, port))
            results.append(f"{Colors.OKBLUE}Port{Colors.ENDC} {port}: {Colors.OKGREEN}Open{Colors.ENDC}")
        except:
            results.append(f"{Colors.OKBLUE}Port{Colors.ENDC} {port}: {Colors.FAIL}Closed{Colors.ENDC}")
        s.close()
    return results

# Find DNS Records by Domain Name
def find_dns_registers(domain_name):
    try:
        registers = {}
        results = []

        # A Records
        a_records = dns.resolver.resolve(domain_name, 'A')
        registers['A'] = [str(rdata) for rdata in a_records]
        results.append(f"{Colors.OKBLUE}A Records: {Colors.HEADER}{', '.join(registers['A'])}{Colors.ENDC}")

        # MX Records (Mail Exchange Records)
        mx_records = dns.resolver.resolve(domain_name, "MX")
        registers["MX"] = [str(rdata.exchange) for rdata in mx_records]
        results.append(f"{Colors.OKBLUE}MX Records: {Colors.HEADER}{', '.join(registers['MX'])}{Colors.ENDC}")

        # NS Records (Name Server Records)
        ns_records = dns.resolver.resolve(domain_name, "NS")
        registers["NS"] = [str(rdata) for rdata in ns_records]
        results.append(f"{Colors.OKBLUE}NS Records: {Colors.HEADER}{', '.join(registers['NS'])}{Colors.ENDC}")

        # TXT Records
        txt_records = dns.resolver.resolve(domain_name, "TXT")
        registers["TXT"] = [str(rdata) for rdata in txt_records]
        results.append(f"{Colors.OKBLUE}TXT Records: {Colors.HEADER}{', '.join(registers['TXT'])}{Colors.ENDC}")

        return results
    except dns.resolver.NoAnswer:
        return [f"{Colors.WARNING}No DNS Records Found...{Colors.ENDC}"]
    except Exception as e:
        return [str(e)]

# SSL Certificate Info
def ssl_certificate_info(domain_name):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain_name, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain_name) as ssock:
                cert = ssock.getpeercert()
        results = [
            f"{Colors.OKBLUE}Issuer: {cert['issuer']}{Colors.ENDC}",
            f"{Colors.OKBLUE}Subject: {cert['subject']}{Colors.ENDC}",
            f"{Colors.OKBLUE}Valid From: {cert['notBefore']}{Colors.ENDC}",
            f"{Colors.OKBLUE}Valid Until: {cert['notAfter']}{Colors.ENDC}"
        ]
        return results
    except ssl.SSLError as e:
        return [str(e)]

# Find Subdomains by Domain Name
def find_subdomains(domain_name):
    url = f"https://crt.sh/?q=%25.{domain_name}&output=json"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            subdomains = set()
            for entry in data:
                name_value = entry.get('name_value', '')
                subdomains.update(name_value.split('\n'))
            return [f"{Colors.OKBLUE}Subdomain{Colors.ENDC}: {Colors.BOLD}{subdomain}{Colors.ENDC}" for subdomain in subdomains]
        else:
            return [f"{Colors.WARNING}Subdomain Search Failed{Colors.ENDC}"]
    except Exception as e:
        return [str(e)]

# Reverse IP lookup by domain name
def reverse_ip_lookup(domain_name):
    ip = socket.gethostbyname(domain_name)
    if not ip:
        return ["Not Found IP Address !!"]
    try:
        url = f"{Colors.HEADER}https://api.hackertarget.com/reverseiplookup/?q={ip}{Colors.ENDC}"
        response = requests.get(url)
        return response.text.splitlines() if response.status_code == 200 else ["Reverse IP Lookup Failed"]
    except Exception as e:
        return [str(e)]

# Main Menu for all functions
def main_menu():
    while True:
        
        choice = input(f"""{Colors.WARNING}
Please select the action you want to perform on the domain:
1 - Whois Query
2 - Find Domain IP Address
3 - Scan Common Ports
4 - DNS Record Query
5 - SSL Certificate Information
6 - Find Subdomains
7 - Reverse IP Lookup
8 - Exit Program
You are researching for:{domain}
Your Selection: {Colors.ENDC}""")
        
        if domain != "":
            if choice == "1":
                lines = whois_query(domain_name=domain)
                print_with_delay(lines)
            elif choice == "2":
                lines = get_ip(domain_name=domain)
                print_with_delay(lines)
            elif choice == "3":
                lines = scan_ports(domain_name=domain)
                print_with_delay(lines)
            elif choice == "4":
                lines = find_dns_registers(domain_name=domain)
                print_with_delay(lines)
            elif choice == "5":
                lines = ssl_certificate_info(domain_name=domain)
                print_with_delay(lines)
            elif choice == "6":
                lines = find_subdomains(domain_name=domain)
                print_with_delay(lines)
            elif choice == "7":
                lines = reverse_ip_lookup(domain_name=domain)
                print_with_delay(lines)
            elif choice == "8":
                print("Exiting program...")
                
            else:
                print("Invalid selection. Please try again.")
        else:
            print("Domain Name Can Not Be Empty !")

# Run the main program
check_root()
print(greeting)
domain = input(f"{Colors.BOLD}Please Enter Domain Name:{Colors.ENDC} ")
if domain != "":
    main_menu()
else:
    print("Domain Name Can Not Be Empty !!")
