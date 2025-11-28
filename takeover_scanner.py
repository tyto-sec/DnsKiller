#!/usr/bin/env python3

import subprocess
import os
import argparse
import csv
import sys


NUCLEI_TEMPLATE_DIR = os.path.expanduser("~/nuclei-templates/http/takeovers")
OUTPUT_DIR = "takeover_output"
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

def enum_subdomains(domain_list_file):
    print("[*] Subdomain enumeration...")
    output_file = os.path.join(OUTPUT_DIR, "subs.txt")
    cmd = f"subfinder -dL {domain_list_file} | anew"
    subs = run_cmd(cmd)
    if subs:
        with open(output_file, "w") as f:
            f.write(subs)
    print(f"[DEBUG] Found {len(subs.splitlines())} subdomains.")
    return output_file

def dns_enum(subdomains_file):
    print("[*] CNAMEs and TXTs enumeration...")
    output_file = os.path.join(OUTPUT_DIR, "dns_records.txt")
    cmd = f"dnsx -cname -txt -silent -re -l {subdomains_file} -o {output_file}"
    run_cmd(cmd)
    return output_file

def filter_takeover_candidates_step(dns_file):
    print("[*] Filtering candidates...")
    candidates_file = os.path.join(OUTPUT_DIR, "takeover_candidates.txt")
    
    host_cname_pairs = []
    import re
    
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
            with open(candidates_file, "w") as f:
                for pair in unique_pairs:
                    f.write(f"{pair}\n")
            print(f"[DEBUG] Found {len(unique_pairs)} unique host->CNAME pairs")
        else:
            print("[!] No CNAME candidates found")
            with open(candidates_file, "w") as f:
                f.write("")
            
    except Exception as e:
        print(f"[!] Error processing DNS file: {e}")
        
    return candidates_file

def get_takeover_candidates_hosts(candidates_file):
    candidates_hosts = []
    try:
        with open(candidates_file, "r") as f:
            for line in f:
                if '->' in line:
                    host = line.split('->')[0].strip()
                    candidates_hosts.append(host)
    except Exception as e:
        print(f"[!] Error loading takeover candidates: {e}")
    candidates_hosts_file = os.path.join(OUTPUT_DIR, "takeover_candidates_hosts.txt")
    with open(candidates_hosts_file, "w") as f:
        for host in candidates_hosts:
            f.write(f"{host}\n")
    return candidates_hosts_file


def map_hosts_to_providers(candidates_file):

    print("[*] Mapping CNAMEs to potential providers...")

    providers_map_file = os.path.join(OUTPUT_DIR, "cnames_providers_map.txt")
    
    CNAME_FINGERPRINTS = {
        "aftership": "AfterShip",
        "agilecrm\\.com": "AgileCRM",
        "aha\\.io": "Aha!",
        "airee\\.com": "Airee",
        "animaapp\\.com": "Anima",
        "announcekit\\.app": "AnnounceKit",
        "s3\\.amazonaws\\.com": "AWS_S3",
        "aws-bucket": "AWS_S3",
        "bigcartel\\.com": "BigCartel",
        "bitbucket\\.io": "Bitbucket",
        "campaignmonitor\\.com": "CampaignMonitor",
        "canny\\.io": "Canny",
        "cargo\\.site": "Cargo",
        "cargocollective\\.com": "CargoCollective",
        "clever-cloud\\.com": "Clever Cloud",
        "flexbe\\.net": "Flexbe",
        "framer\\.cloud": "Framer",
        "frontify\\.com": "Frontify",
        "gemfury\\.com": "Gemfury",
        "getresponsepages\\.com": "GetResponse",
        "ghost\\.io": "Ghost",
        "gitbook\\.io": "GitBook",
        "github\\.io": "GitHub_Pages",
        "gohire\\.io": "GoHire",
        "greatpages\\.com\\.br": "GreatPages",
        "hatenablog\\.com": "Hatenablog",
        "helpdocs\\.io": "HelpDocs",
        "helpjuice\\.com": "HelpJuice",
        "helprace\\.com": "Helprace",
        "helpscoutdocs\\.com": "HelpScout",
        "hubspot\\.net": "HubSpot",
        "intercom\\.website": "Intercom",
        "jazzhr\\.com": "JazzHR",
        "jetbrains\\.com": "JetBrains",
        "kinsta\\.cloud": "Kinsta",
        "launchrock\\.com": "Launchrock",
        "leadpages\\.net": "Leadpages",
        "mailgun\\.org": "Mailgun",
        "mashery\\.com": "Mashery",
        "meteor\\.com": "Meteor",
        "netlify\\.com": "Netlify",
        "ngrok\\.io": "Ngrok",
        "pagewiz\\.com": "Pagewiz",
        "pantheonsite\\.io": "Pantheon",
        "pingdom\\.com": "Pingdom",
        "proposify\\.biz": "Proposify",
        "readthedocs\\.io": "ReadTheDocs",
        "redirect-pizza\\.com": "RedirectPizza",
        "myshopify\\.com": "Shopify",
        "short\\.io": "ShortIO",
        "simplebooklet\\.com": "Simplebooklet",
        "smartjob\\.com": "SmartJobBoard",
        "smugmug\\.com": "SmugMug",
        "softr\\.io": "Softr",
        "sprintful\\.com": "Sprintful",
        "squadcast\\.io": "Squadcast",
        "strikinglydn\\.com": "Strikingly",
        "surge\\.sh": "Surge",
        "surveygizmo\\.com": "SurveyGizmo",
        "surveysparrow\\.com": "SurveySparrow",
        "tave\\.com": "Tave",
        "teamwork\\.com": "Teamwork",
        "tilda\\.ws": "Tilda",
        "uberflip\\.com": "Uberflip",
        "uptime\\.com": "Uptime",
        "uptimerobot\\.com": "UptimeRobot",
        "uservoice\\.com": "UserVoice",
        "vendcommerce\\.com": "Vend",
        "wasabisys\\.com": "Wasabi_S3",
        "wishpond\\.com": "Wishpond",
        "wixsite\\.com": "Wix",
        "wordpress\\.com": "WordPress",
        "wufoo\\.com": "Wufoo",
        "zendesk\\.com": "Zendesk",
        
        # Generic Cloud / PaaS
        "cloudapps\\.net": "Azure",
        "azurewebsites\\.net": "Azure",
        "cloudapp\\.net": "Azure",
        "cloudapp\\.com": "Azure",
        "azureedge\\.net": "Azure", 
        "azurefd\\.net": "Azure",
        "azurestaticapps\\.net": "Azure",
        "cloudapp\\.azure\\.com": "Azure",
        "ghs\\.googlehosted\\.com": "Google_Apps",
        "storage\\.googleapis\\.com": "Google_Cloud_Storage",
        "storage\\.azure\\.net": "Azure_Storage",
        "trafficmanager\\.net": "Azure_Traffic_Manager",
        "awsglobalaccelerator\\.com": "AWS_Global_Accelerator",
        "s3-website-": "AWS_S3", # Sufixo comum para S3 Static Hosting
        "herokudns\\.com": "Heroku",
        "herokuapp\\.com": "Heroku",
        "pages\\.dev": "Cloudflare_Pages",
        "read\\.link": "Read.Link",
        "wpengine\\.com": "WPEngine",

        # E-commerce e Marketing (Variações)
        "instapage\\.com": "Unbounce/Instapage",
        "unbouncepages\\.com": "Unbounce",
        "getresponse\\.com": "GetResponse",
        
        # Suporte (Variações)
        "desk\\.com": "Zendesk", 
        "freshdesk\\.com": "Freshdesk",
        "freshservice\\.com": "Freshdesk",
        "dot-docs\\.com": "HelpDocs",
        
        # Outros (Variações)
        "pagecdn\\.io": "PageCDN",
        "cname\\.vercel-dns\\.com": "Vercel",
        "custom\\.bnc\\.lt": "Branch",
        "acquia-sites\\.com": "Acquia",
        "readthedocsonline\\.com": "ReadTheDocs", # Variação ReadTheDocs
    }
    
    regex_pattern = '|'.join([f"->.*{kw}" for kw in susceptible_keywords])
    
    cmd = (
        f"grep -iE '{regex_pattern}' {candidates_file} | sort -u > {grepped_candidates_file}"
    )

    run_cmd(cmd)

    if os.path.exists(grepped_candidates_file) and os.stat(grepped_candidates_file).st_size > 0:
        count = len(open(grepped_candidates_file).readlines())
        print(f"[!] Found {count} candidates based on CNAME keyword filtering. Results in {grepped_candidates_file}")
    else:
        print(f"[!] No high-potential candidates found based on CNAME filtering.")
        
    return grepped_candidates_file

def get_grepped_candidates_hosts(grepped_candidates_file):
    grepped_candidates_hosts = []
    try:
        with open(grepped_candidates_file, "r") as f:
            for line in f:
                if '->' in line:
                    host = line.split('->')[0].strip()
                    grepped_candidates_hosts.append(host)
    except Exception as e:
        print(f"[!] Error loading grepped takeover candidates: {e}")
    grepped_candidates_hosts_file = os.path.join(OUTPUT_DIR, "grepped_takeover_candidates_hosts.txt")
    with open(grepped_candidates_hosts_file, "w") as f:
        for host in grepped_candidates_hosts:
            f.write(f"{host}\n")
    return grepped_candidates_hosts_file

def check_online_hosts(grepped_candidates_hosts_file):
    print("[*] Checking online hosts...")
    online_file = os.path.join(OUTPUT_DIR, "online_candidates.txt")
    cmd = f"httpx -silent -l {grepped_candidates_hosts_file}"
    output = run_cmd(cmd)
    if output:
        with open(online_file, "w") as f:
            f.write(output)
    print(f"[DEBUG] Found {len(output.splitlines())} online hosts.")
    return online_file

def run_nuclei_scan(grepped_candidates_hosts_file):
    print("[*] Executing nuclei scan...")
    csv_file = os.path.join(OUTPUT_DIR, "final_results.csv")
    results = []

    for host in read_domains(grepped_candidates_hosts_file):
        vulnerable = "not vulnerable"
        cmd = f"nuclei -u {host} -t {NUCLEI_TEMPLATE_DIR} -silent"
        result = run_cmd(cmd)
        if result:
            vulnerable = "vulnerable"
            output_path = os.path.join(OUTPUT_DIR, f"{host.replace('http://','').replace('https://','').replace('/','_')}_takeover.txt")
            with open(output_path, "w") as f:
                f.write(result)
            print(f"[!] Result saved in: {output_path}")
        results.append([host, vulnerable, ""])

    with open(csv_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Subdomain", "Nuclei Result", "Manual Verification"])
        writer.writerows(results)

    print(f"[+] CSV report saved in: {csv_file}")

def main(domains_file):
    print("[+] Starting automated Subdomain Takeover scanner...")

    subs_file = enum_subdomains(domains_file)
    dns_file = dns_enum(subs_file)
    candidates_file = filter_takeover_candidates_step(dns_file)
    candidates_hosts_file = get_takeover_candidates_hosts(candidates_file)
    grepped_candidates_file = identify_vulnerable_cnames(candidates_file)
    grepped_candidates_hosts_file = get_grepped_candidates_hosts(grepped_candidates_file)
    online_file = check_online_hosts(grepped_candidates_hosts_file)
    run_nuclei_scan(online_file)

    print("[+] Process completed. Check the 'takeover_output' directory for results.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automated Subdomain Takeover Scanner")
    parser.add_argument("-f", "--file", required=True, help="File containing list of domains")
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"[!] File {args.file} not found.")
        sys.exit(1)

    main(args.file)