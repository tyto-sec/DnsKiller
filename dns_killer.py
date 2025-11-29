#!/usr/bin/env python3

import subprocess
import os
import argparse
import csv
import sys
from constants import CNAME_FINGERPRINTS
from constants import TAKEOVER_MAP
import re
import concurrent.futures

NUCLEI_TEMPLATE_DIR = os.path.expanduser("~/nuclei-templates/http/takeovers")
OUTPUT_DIR = "output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        print(f"[!] Error executing: {cmd}\n{e}")
        return ""

def read_domains(file_path):
    with open(file_path, "r") as f:
        return [line.strip() for line in f.readlines() if line.strip()]

def enum_subdomains(domain, domain_output_dir):
    print("[*] Subdomain enumeration...")
    output_file = os.path.join(domain_output_dir, "subs.txt")
    cmd = f"subfinder -d {domain} | anew"
    subs = run_cmd(cmd)
    if subs:
        with open(output_file, "w") as f:
            f.write(subs)
    print(f"[DEBUG] Found {len(subs.splitlines())} subdomains.")
    return output_file

def dns_enum(subdomains_file, domain_output_dir):
    if not os.path.isfile(subdomains_file):
        print(f"[!] Subdomains file {subdomains_file} not found for DNS enumeration.")
        return ""
    print("[*] CNAMEs and TXTs enumeration...")
    output_file = os.path.join(domain_output_dir, "dns_records.txt")
    cmd = f"dnsx -cname -txt -silent -re -l {subdomains_file} -o {output_file}"
    run_cmd(cmd)
    return output_file

def get_hosts_with_permissive_spf(dns_file, domain_output_dir):
    if not os.path.isfile(dns_file):
        print(f"[!] DNS records file {dns_file} not found for SPF filtering.")
        return ""
    print("[*] Filtering SPF permissive candidates...")
    spf_hosts_file = os.path.join(domain_output_dir, "spf_permissive_hosts.txt")
    spf_host_records = [] 
    spf_hosts = [] 
    try:
        with open(dns_file, 'r') as f:
            for line in f:
                if 'TXT' in line.upper() and 'V=SPF1' in line.upper():
                    clean_line = re.sub(r'\x1b\[[0-9;]*m', '', line)
                    clean_line = re.sub(r'[\[\]]', '', clean_line)
                    
                    parts = clean_line.strip().split()
                    if len(parts) >= 3:
                        host = parts[0]
                        txt_record = ' '.join(parts[2:])
                        if any(term in txt_record.lower() for term in ['~all', '?all']):
                            spf_host_records.append(f"{host} -> {txt_record}")
                            spf_hosts.append(host)
        unique_spf_records = []
        seen_hosts = set()
        for record in spf_host_records:
            host = record.split(' -> ')[0]
            if host not in seen_hosts:
                unique_spf_records.append(record)
                seen_hosts.add(host)
        if unique_spf_records:
            with open(spf_hosts_file, "w") as f:
                for record in unique_spf_records:
                    f.write(f"{record}\n")
            print(f"[DEBUG] Found {len(unique_spf_records)} SPF permissive hosts with records.")
        else:
            print("[!] No SPF permissive candidates found")
            with open(spf_hosts_file, "w") as f:
                f.write("")
    except Exception as e:
        print(f"[!] Error processing DNS file for SPF: {e}")
    return spf_hosts_file

def get_hosts_with_spf_list(spf_hosts_file, domain_output_dir):
    if not os.path.isfile(spf_hosts_file):
        print(f"[!] SPF hosts file {spf_hosts_file} not found for SPF host list extraction.")
        return ""
    spf_hosts = []
    spf_hosts_list_file = os.path.join(domain_output_dir, "spf_permissive_hosts_list.txt")
    try:
        with open(spf_hosts_file, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    if ' -> ' in line:
                        host = line.split(' -> ')[0].strip()
                    else:
                        host = line 
                    if host:
                        spf_hosts.append(host)
    except Exception as e:
        print(f"[!] Error loading SPF permissive candidates: {e}")
    with open(spf_hosts_list_file, "w") as f:
        for host in spf_hosts:
            f.write(f"{host}\n")
    print(f"[DEBUG] Extracted {len(spf_hosts)} SPF permissive hosts.")
    return spf_hosts_list_file

def get_hosts_with_cname(dns_file, domain_output_dir):
    if not os.path.isfile(dns_file):
        print(f"[!] DNS records file {dns_file} not found for CNAME filtering.")
        return ""
    print("[*] Filtering candidates...")
    cname_hosts_pairs_file = os.path.join(domain_output_dir, "cname_hosts_pairs.txt")
    host_cname_pairs = []
    try:
        with open(dns_file, 'r') as f:
            for line in f:
                if 'CNAME' in line:
                    clean_line = re.sub(r'\x1b\[[0-9;]*m', '', line)
                    clean_line = re.sub(r'[\[\]]', '', clean_line)
                    
                    parts = clean_line.strip().split()
                    if len(parts) >= 3: 
                        host = parts[0]
                        cname = parts[-1]
                        if host and cname and '.' in cname:
                            host_cname_pairs.append(f"{host} -> {cname}")
        unique_pairs = sorted(set(host_cname_pairs))
        if unique_pairs:
            with open(cname_hosts_pairs_file, "w") as f:
                for pair in unique_pairs:
                    f.write(f"{pair}\n")
            print(f"[DEBUG] Found {len(unique_pairs)} unique Host -> CNAME pairs")
        else:
            print("[!] No CNAME candidates found")
            with open(cname_hosts_pairs_file, "w") as f:
                f.write("")
    except Exception as e:
        print(f"[!] Error processing DNS file: {e}")
    return cname_hosts_pairs_file

def get_hosts_with_cname_list(cname_hosts_pairs_file, domain_output_dir):
    if not os.path.isfile(cname_hosts_pairs_file):
        print(f"[!] CNAME hosts pairs file {cname_hosts_pairs_file} not found for CNAME host list extraction.")
        return ""
    cname_hosts = []
    cname_hosts_file = os.path.join(domain_output_dir, "cname_hosts.txt")
    try:
        with open(cname_hosts_pairs_file, "r") as f:
            for line in f:
                if '->' in line:
                    host = line.split('->')[0].strip()
                    cname_hosts.append(host)
    except Exception as e:
        print(f"[!] Error loading takeover candidates: {e}")
    with open(cname_hosts_file, "w") as f:
        for host in cname_hosts:
            f.write(f"{host}\n")
    print(f"[DEBUG] Extracted {len(cname_hosts)} cname hosts.")
    return cname_hosts_file

def get_grepped_cname_hosts_pairs(cname_hosts_pairs_file, domain_output_dir):
    if not os.path.isfile(cname_hosts_pairs_file):
        print(f"[!] CNAME hosts pairs file {cname_hosts_pairs_file} not found for grepping.")
        return ""
    print("[*] Performing massive grep filtering on CNAME targets based on master list...")
    grepped_cname_hosts_pairs_file = os.path.join(domain_output_dir, "grepped_cname_hosts_pairs_file.txt")
    all_cname_keywords = []
    for cname_list in CNAME_FINGERPRINTS.values():
        all_cname_keywords.extend(cname_list)
    unique_cname_keywords = sorted(list(set(all_cname_keywords)))
    regex_pattern = '|'.join(unique_cname_keywords)
    cmd = (
        f"grep -iE \"({regex_pattern})\" {cname_hosts_pairs_file} | sort -u > {grepped_cname_hosts_pairs_file}"
    )
    run_cmd(cmd)
    print(f"[DEBUG] Grepped {len(grepped_cname_hosts_pairs_file.splitlines())} candidates.")
    return grepped_cname_hosts_pairs_file

def get_grepped_cname_hosts(grepped_cname_hosts_pairs_file, domain_output_dir):
    if not os.path.isfile(grepped_cname_hosts_pairs_file):
        print(f"[!] Grepped CNAME hosts pairs file {grepped_cname_hosts_pairs_file} not found for host extraction.")
        return ""
    grepped_cname_hosts_file = os.path.join(domain_output_dir, "grepped_takeover_cname_hosts.txt")
    grepped_cname_hosts = []
    try:
        with open(grepped_cname_hosts_pairs_file, "r") as f:
            for line in f:
                if '->' in line:
                    host = line.split('->')[0].strip()
                    grepped_cname_hosts.append(host)
    except Exception as e:
        print(f"[!] Error loading grepped takeover candidates: {e}")
    with open(grepped_cname_hosts_file, "w") as f:
        for host in grepped_cname_hosts:
            f.write(f"{host}\n")
    return grepped_cname_hosts_file

def check_online_hosts(grepped_cname_hosts_file, domain_output_dir):
    if not os.path.isfile(grepped_cname_hosts_file):
        print(f"[!] Grepped CNAME hosts file {grepped_cname_hosts_file} not found for online checking.")
        return ""
    print("[*] Checking online hosts...")
    online_file = os.path.join(domain_output_dir, "online_candidates.txt")
    cmd = f"httpx -silent -l {grepped_cname_hosts_file}"
    output = run_cmd(cmd)
    if output:
        with open(online_file, "w") as f:
            f.write(output)
    print(f"[DEBUG] Found {len(output.splitlines())} online hosts.")
    return online_file

def run_nuclei_scan(online_hosts_file, cname_hosts_pairs_file, domain_output_dir):
    if not os.path.isfile(online_hosts_file):
        print(f"[!] Online hosts file {online_hosts_file} not found for nuclei scanning.")
        return
    if not os.path.isfile(cname_hosts_pairs_file):
        print(f"[!] CNAME hosts pairs file {cname_hosts_pairs_file} not found for nuclei scanning.")
        return
    print("[*] Executing targeted nuclei scan...")
    csv_file = os.path.join(domain_output_dir, "final_results.csv")
    results = []
    host_to_cname = {}
    try:
        with open(cname_hosts_pairs_file, 'r') as f:
            for line in f:
                if '->' in line:
                    host, cname = [p.strip() for p in line.split('->', 1)]
                    host_to_cname[host] = cname
    except Exception as e:
        print(f"[!] Erro ao carregar pares Host -> CNAME: {e}")
        return
    for host_url in read_domains(online_hosts_file):
        host = host_url.split('//')[-1].split('/')[0]
        cname_target = host_to_cname.get(host)
        nuclei_template = None
        provider_name = "Unknown"
        if cname_target:
            for provider, cnames in CNAME_FINGERPRINTS.items():
                for cname_regex in cnames:
                    if re.search(cname_regex, cname_target, re.IGNORECASE):
                        provider_name = provider
                        nuclei_template = TAKEOVER_MAP.get(provider_name)
                        break
                if nuclei_template:
                    break
        if nuclei_template:
            template_path = os.path.join(NUCLEI_TEMPLATE_DIR, nuclei_template) 
            cmd = f"nuclei -u {host} -t {template_path}"
            print(f"[*] Testing {host} against {provider_name} template: {nuclei_template}")
            try:
                result = run_cmd(cmd)
                vulnerable = "NOT Vulnerable"
                if result:
                    vulnerable = f"VULNERABLE ({provider_name})"
                    output_path = os.path.join(OUTPUT_DIR, f"{host.split(':')[0]}_vulnerable_{provider_name}.txt")
                    with open(output_path, "w") as f:
                        f.write(result)
                    print(f"  [!!!] VULNERABLE! Result saved in: {output_path}")
                results.append([host, cname_target, provider_name, template_path, vulnerable])
            except Exception as e:
                print(f"[!] Error running nuclei for {host}: {e}")
                results.append([host, cname_target, provider_name, template_path, f"Error: {str(e)}"])
        else:
            print(f"[*] Skipped {host} (CNAME: {cname_target}) - No specific nuclei template found for provider: {provider_name}")
            results.append([host, cname_target if cname_target else "N/A", provider_name, "N/A", "Skipped (No Template)"])

    with open(csv_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Subdomain", "CNAME Target", "Provider", "Nuclei Template", "Vulnerability Status"])
        writer.writerows(results)

    print(f"[+] CSV report saved in: {csv_file}")

def process_single_domain(domain):
    domain_name_safe = domain.replace('.', '_')
    domain_output_dir = os.path.join(OUTPUT_DIR, domain_name_safe)
    
    os.makedirs(domain_output_dir, exist_ok=True)

    print(f"\n[+] Processing domain: {domain}")
    print(f"[*] Output directory: {domain_output_dir}")
    
    try:
        subs_file = enum_subdomains(domain, domain_output_dir)
        dns_file = dns_enum(subs_file, domain_output_dir)
        dns_file_abs = os.path.join(domain_output_dir, os.path.basename(dns_file))
        spf_hosts_file = get_hosts_with_permissive_spf(dns_file_abs, domain_output_dir)
        spf_hosts_file_abs = os.path.join(domain_output_dir, os.path.basename(spf_hosts_file))
        get_hosts_with_spf_list(spf_hosts_file_abs, domain_output_dir)
        cname_hosts_pairs_file = get_hosts_with_cname(dns_file_abs, domain_output_dir)
        cname_hosts_pairs_file_abs = os.path.join(domain_output_dir, os.path.basename(cname_hosts_pairs_file))
        get_hosts_with_cname_list(cname_hosts_pairs_file_abs, domain_output_dir)
        grepped_cname_hosts_pairs_file = get_grepped_cname_hosts_pairs(cname_hosts_pairs_file_abs, domain_output_dir)
        grepped_cname_hosts_pairs_file_abs = os.path.join(domain_output_dir, os.path.basename(grepped_cname_hosts_pairs_file))
        grepped_cname_hosts_file = get_grepped_cname_hosts(grepped_cname_hosts_pairs_file_abs, domain_output_dir)
        grepped_cname_hosts_file_abs = os.path.join(domain_output_dir, os.path.basename(grepped_cname_hosts_file))
        online_file = check_online_hosts(grepped_cname_hosts_file_abs, domain_output_dir)
        online_file_abs = os.path.join(domain_output_dir, os.path.basename(online_file))
        run_nuclei_scan(online_file_abs, grepped_cname_hosts_pairs_file_abs, domain_output_dir)
        
        return f"[+] Domain {domain} completed successfully."
        
    except Exception as e:
        return f"[!] Error processing domain {domain}: {e}"
    
def main(domains_file):
    print("[+] Starting automated Subdomain Takeover scanner...")
    
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    MAX_THREADS = 8
    domains_list = read_domains(domains_file)
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        print(f"[*] Processing {len(domains_list)} domains with a maximum of {MAX_THREADS} parallel threads.")
        
        results = executor.map(process_single_domain, domains_list)
        for result in results:
            print(result)

    print("\n[+] Process completed. Check the 'takeover_output' directory for results.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automated Subdomain Takeover Scanner")
    parser.add_argument("-f", "--file", required=True, help="File containing list of domains")
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"[!] File {args.file} not found.")
        sys.exit(1)

    main(args.file)