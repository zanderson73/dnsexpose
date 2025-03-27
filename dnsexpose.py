!/usr/bin/env python3

import dns.resolver
import dns.query
import dns.zone
import dns.name
import dns.exception
import subprocess
import json
import sys
from tabulate import tabulate

BANNER = r'''
  ____  _   _ ____  _____                 
 |  _ \| \ | |  _ \| ____|_ __  ___  ___ 
 | | | |  \| | | | |  _| | '_ \/ __|/ _ \
 | |_| | |\  | |_| | |___| | | \__ \  __/
 |____/|_| \_|____/|_____|_| |_|___/\___|

    dnsexpose.py - DNS Recon & AXFR Scanner
        Red Team Utility by zane Anderson
'''

def get_records(domain, record_type):
    try:
        answers = dns.resolver.resolve(domain, record_type, raise_on_no_answer=False)
        return [str(r.to_text()) for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return []
    except Exception as e:
        return [f"Error: {str(e)}"]

def attempt_axfr(domain, ns_servers):
    axfr_results = {}
    for ns in ns_servers:
        try:
            z = dns.zone.from_xfr(dns.query.xfr(ns.rstrip('.')))
            axfr_results[ns] = list(z.nodes.keys())
        except Exception:
            axfr_results[ns] = "Zone transfer failed or not allowed: "
    return axfr_results

def dig_txt(domain):
    try:
        result = subprocess.check_output(["dig", domain, "TXT"], universal_newlines=True)
        return result.strip()
    except subprocess.CalledProcessError:
        return "dig failed"

def nslookup_txt(domain):
    try:
        result = subprocess.check_output(["nslookup", "-type=TXT", domain], universal_newlines=True)
        return result.strip()
    except subprocess.CalledProcessError:
        return "nslookup failed"

def check_dnssec(domain):
    try:
        dnskey = dns.resolver.resolve(domain, 'DNSKEY', raise_on_no_answer=False)
        if dnskey.rrset:
            return True
    except:
        pass
    return False

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <domain>")
        sys.exit(1)

    domain = sys.argv[1]

    print(BANNER)
    print(f"[*] Enumerating DNS records for: {domain}\n")

    records = {
        "A": get_records(domain, "A"),
        "AAAA": get_records(domain, "AAAA"),
        "MX": get_records(domain, "MX"),
        "NS": get_records(domain, "NS"),
        "PTR": get_records(domain, "PTR"),
        "SOA": get_records(domain, "SOA"),
        "TXT": get_records(domain, "TXT"),
        "CNAME": get_records(domain, "CNAME"),
        "HINFO": get_records(domain, "HINFO"),
        "ISDN": get_records(domain, "ISDN")
    }

    print("[*] Testing for AXFR on NS servers...\n")
    axfr_results = attempt_axfr(domain, records["NS"])

    print("[*] Running dig and nslookup for TXT records...\n")
    dig_output = dig_txt(domain)
    nslookup_output = nslookup_txt(domain)

    dnssec_enabled = check_dnssec(domain)

    print("[*] DNS Enumeration Summary:\n")
    for record_type, values in records.items():
        print(f"{record_type} Records:")
        if values:
            print(tabulate([[i+1, v] for i, v in enumerate(values)], headers=["#", record_type]))
        else:
            print("  No records found.\n")

    print("[*] AXFR Results:\n")
    for ns, result in axfr_results.items():
        print(f"NS: {ns}\n  {result}\n")

    print("[*] DNSSEC Support:")
    if dnssec_enabled:
        print(f"  ✔ DNSSEC is enabled for {domain}\n")
    else:
        print(f"  ✘ DNSSEC is not enabled for {domain}\n")

    print("[*] External Query Results (dig/nslookup):\n")
    print("-- dig_txt --\n" + dig_output + "\n")
    print("-- nslookup_txt --\n" + nslookup_output + "\n")

    # Save results to JSON
    output = {
        "domain": domain,
        "records": records,
        "zone_transfer": axfr_results,
        "dnssec": "Enabled" if dnssec_enabled else "Not enabled",
        "dig_txt": dig_output,
        "nslookup_txt": nslookup_output
    }

    with open(f"dnsexpose_{domain}.json", "w") as f:
        json.dump(output, f, indent=2)

    print(f"[*] Results saved to dnsexpose_{domain}.json")

if __name__ == "__main__":
    main()

