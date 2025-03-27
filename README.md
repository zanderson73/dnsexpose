# dnsexpose.py

**dnsexpose.py** is a Red Team-focused DNS enumeration and zone transfer auditing tool written in Python.
It performs deep DNS reconnaissance by collecting records, probing for misconfigured AXFR transfers, and integrating external tools like `dig` and `nslookup` to bypass filtered resolution.

---

## Features

- Enumerates core DNS records: `A`, `AAAA`, `MX`, `NS`, `PTR`, `SOA`, `TXT`, `CNAME`, `HINFO`, `ISDN`
- Attempts AXFR zone transfers from NS records
- Uses `dig` and `nslookup` to verify TXT records externally
- Outputs results to CLI **and** JSON file (`dnsexpose_<domain>.json`)
- Built for speed, clarity, and modular Red Team use

---

## Installation

```bash
pip install dnspython tabulate
```

Ensure `dig` and `nslookup` are available in your PATH (usually included in `dnsutils` or `bind9-host`):
```bash
sudo apt install dnsutils
```

---

## Usage

```bash
python3 dnsexpose.py <target-domain>
```

### Example:
```bash
python3 dnsexpose.py example.com
```

---

## Sample Output
```
[[*] DNS Enumeration Summary:
A Records:
  1  192.0.2.1

AAAA Records:
  1  2001:db8::1

MX Records:
  1  10 mail.example.com.

TXT Records:
  1  "v=spf1 include:_spf.example.com ~all"

[*] AXFR Results:
NS: ns1.example.com
  Zone transfer failed or not allowed

[*] DNSSEC Support:
  ✘ DNSSEC is not enabled for example.com
```

JSON output is saved to `dnsexpose_<domain>.json` for reporting or scripting.

---

## Roadmap
- CLI flags for modular enumeration (e.g. `--only-a`, `--no-axfr`)
- Subdomain brute-forcing
- Passive recon integration (`crt.sh`, `securitytrails`, etc)
- Export to HTML, CSV, or markdown

---

## Contributing
Pull requests and feature suggestions are welcome! Please fork and submit via PR.

---

## 🧑‍💻 Author
**Zane Anderson**  
Operational Red Teamer / Red Team Developer / Security Researcher  
📧 Email: zanderson@iscsecurity.org  
🔗 GitHub: [zanderson73](https://github.com/zanderson73)

---

## 📜 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

