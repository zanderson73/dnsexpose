#!/usr/bin/env python3

import dns.resolver
import dns.query
import dns.zone
import json
import sys
import subprocess
from tabulate import tabulate

def banner():
    print(r"""
      ____  _   _ ____  _____                 
     |  _ \| \ | |  _ \| ____|_ __  ___  ___ 
     | | | |  \| | | | |  _| | '_ \/ __|/ _ \
     | |_| | |\  | |_| | |___| | | \__ \  __/
     |____/|_| \_|____/|_____|_| |_|___/\___|

        dnsexpose.py - DNS Recon & AXFR Scanner
            Red Team Utility by zane Anderson
    """)

def get_records(domain):
    record_types = ['A', 'AAAA', 'CNAME', 'HINFO', 'ISDN', 'MX', 'NS', 'PTR', 'SOA', 'TXT']
    records = {}
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype, raise_on_no_answer=False)
            records[rtype] = [r.to_text() for r in answers]
        except:
            records[rtype] = []
    return records

def test_zone_transfer(domain, ns_servers):
    axfr_results = {}
    for ns in ns_servers:
        ns_host = ns.rstrip('.')
        try:
            z = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, lifetime=5))
            axfr_results[ns_host] = [str(n) for n in z.nodes.keys()]
        except Exception as e:
            axfr_results[ns_host] = f"Zone transfer failed or not allowed: {e}"
    return axfr_results

def run_external_queries(domain):
    external_results = {}
    try:
        dig_output = subprocess.check_output(['dig', domain, 'TXT'], text=True)
        external_results['dig_txt'] = dig_output.strip()
    except Exception as e:
        external_results['dig_txt'] = f"dig command failed: {e}"

    try:
        nslookup_output = subprocess.check_output(['nslookup', '-type=TXT', domain], text=True)
        external_results['nslookup_txt'] = nslookup_output.strip()
    except Exception as e:
        external_results['nslookup_txt'] = f"nslookup command failed: {e}"

    return external_results

def main(domain):
    banner()
    print(f"[*] Enumerating DNS records for: {domain}\n")
    records = get_records(domain)

    print("[*] Testing for AXFR on NS servers...\n")
    axfr_results = test_zone_transfer(domain, records['NS'])

    print("[*] Running dig and nslookup for TXT records...\n")
    external_results = run_external_queries(domain)

    output = {
        'domain': domain,
        'records': records,
        'zone_transfer': axfr_results,
        'external_queries': external_results
    }

    print("[*] DNS Enumeration Summary:\n")
    for k, v in records.items():
        print(f"{k} Records:")
        if v:
            print(tabulate([[i+1, item] for i, item in enumerate(v)], headers=["#", k]))
        else:
            print("  No records found.")
        print()

    print("[*] AXFR Results:\n")
    for ns, result in axfr_results.items():
        print(f"NS: {ns}")
        if isinstance(result, list):
            print(tabulate([[i+1, item] for i, item in enumerate(result)], headers=["#", "Hostnames"]))
        else:
            print(f"  {result}")
        print()

    print("[*] External Query Results (dig/nslookup):\n")
    for tool, result in external_results.items():
        print(f"-- {tool} --")
        print(result)
        print()

    with open(f"dnsexpose_{domain}.json", "w") as f:
        json.dump(output, f, indent=2)
    print(f"[*] Results saved to dnsexpose_{domain}.json")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 dnsexpose.py <target-domain>")
        sys.exit(1)
    main(sys.argv[1])
