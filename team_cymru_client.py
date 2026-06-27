#!/usr/bin/env python3
"""
Team Cymru IP-to-ASN Mapping Client — bulk IP/prefix lookups via DNS and whois.

A Python client for Team Cymru's IP-to-ASN mapping service using DNS TXT queries
(fastest) and whois protocol as fallback for bulk lookups.

No API key required. Uses DNS TXT queries (fastest) and whois protocol as fallback.

Usage:
    python3 team_cymru_client.py --ip 8.8.8.8
    python3 team_cymru_client.py --bulk-ips 8.8.8.8 1.1.1.1 9.9.9.9
    python3 team_cymru_client.py --prefix 1.1.1.0/24
    python3 team_cymru_client.py --asn 13335
    python3 team_cymru_client.py --bulk-file ips.txt

Author: Nikos Leontsinis
License: MIT
"""

import argparse
import json
import sys
import socket
import subprocess


class TeamCymru:
    """Team Cymru IP-to-ASN mapping via DNS TXT and whois."""

    DNS_SUFFIX_V4 = "origin.asn.cymru.com"
    DNS_SUFFIX_V6 = "origin6.asn.cymru.com"
    DNS_SUFFIX_ASN = "peer.asn.cymru.com"
    WHOIS_SERVER = "whois.cymru.com"

    def ip_to_asn_dns(self, ip):
        """Resolve IP to ASN via DNS TXT query. Returns dict with asn, prefix, cc, rir, date."""
        if ":" in ip:
            # IPv6 — expand and reverse nibbles
            parts = self._expand_ipv6(ip)
            qname = "{}.{}".format(parts, self.DNS_SUFFIX_V6)
        else:
            octets = ip.split(".")
            octets.reverse()
            qname = "{}.{}".format(".".join(octets), self.DNS_SUFFIX_V4)
        try:
            answers = socket.getaddrinfo(qname, None, socket.AF_INET, socket.SOCK_STREAM)
            # DNS TXT won't work via getaddrinfo, use subprocess dig/nslookup
            return self._dns_txt_lookup(qname)
        except Exception:
            return self._dns_txt_lookup(qname)

    def _dns_txt_lookup(self, qname):
        """Use dig or nslookup to get TXT record."""
        try:
            out = subprocess.check_output(["dig", "+short", "TXT", qname], timeout=10, stderr=subprocess.DEVNULL)
            txt = out.decode().strip().strip('"')
            return self._parse_cymru_txt(txt)
        except FileNotFoundError:
            try:
                out = subprocess.check_output(["nslookup", "-type=TXT", qname], timeout=10, stderr=subprocess.DEVNULL)
                for line in out.decode().splitlines():
                    if "text" in line.lower() or '"' in line:
                        txt = line.split('"')[1] if '"' in line else line.split("=")[-1].strip()
                        return self._parse_cymru_txt(txt)
            except Exception:
                pass
        return {"error": "DNS lookup failed for {}".format(qname)}

    def _parse_cymru_txt(self, txt):
        """Parse Team Cymru DNS TXT response: 'ASN | PREFIX | CC | RIR | DATE'"""
        if not txt or "error" in txt.lower():
            return {"raw": txt}
        parts = [p.strip() for p in txt.split("|")]
        result = {"raw": txt}
        if len(parts) >= 1:
            result["asn"] = parts[0]
        if len(parts) >= 2:
            result["prefix"] = parts[1]
        if len(parts) >= 3:
            result["cc"] = parts[2]
        if len(parts) >= 4:
            result["rir"] = parts[3]
        if len(parts) >= 5:
            result["allocated"] = parts[4]
        return result

    def _expand_ipv6(self, ip):
        """Expand IPv6 and return reversed nibbles for DNS."""
        import ipaddress
        addr = ipaddress.ip_address(ip)
        full = addr.exploded.replace(":", "")
        nibbles = list(full)
        nibbles.reverse()
        return ".".join(nibbles)

    def asn_name_dns(self, asn):
        """Get AS name via DNS TXT: AS<num>.asn.cymru.com"""
        qname = "AS{}.asn.cymru.com".format(str(asn).replace("AS", "").replace("as", ""))
        return self._dns_txt_lookup(qname)

    def bulk_whois(self, ips):
        """Bulk IP-to-ASN via whois protocol (netcat to whois.cymru.com)."""
        query = "begin\nverbose\n" + "\n".join(ips) + "\nend\n"
        try:
            import socket as s
            sock = s.socket(s.AF_INET, s.SOCK_STREAM)
            sock.settimeout(15)
            sock.connect((self.WHOIS_SERVER, 43))
            sock.sendall(query.encode())
            data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
            sock.close()
            return self._parse_whois_bulk(data.decode())
        except Exception as e:
            return {"error": str(e)}

    def _parse_whois_bulk(self, raw):
        """Parse bulk whois response."""
        results = []
        for line in raw.strip().splitlines():
            if line.startswith("Bulk") or line.startswith("Error") or not line.strip():
                continue
            parts = [p.strip() for p in line.split("|")]
            entry = {"raw": line}
            if len(parts) >= 1:
                entry["asn"] = parts[0]
            if len(parts) >= 2:
                entry["ip"] = parts[1]
            if len(parts) >= 3:
                entry["prefix"] = parts[2]
            if len(parts) >= 4:
                entry["cc"] = parts[3]
            if len(parts) >= 5:
                entry["rir"] = parts[4]
            if len(parts) >= 6:
                entry["allocated"] = parts[5]
            if len(parts) >= 7:
                entry["as_name"] = parts[6]
            results.append(entry)
        return results

    def prefix_to_asn(self, prefix):
        """Lookup ASN for a prefix via DNS (uses first IP in prefix)."""
        import ipaddress
        net = ipaddress.ip_network(prefix, strict=False)
        first_ip = str(net.network_address)
        return self.ip_to_asn_dns(first_ip)


def main():
    parser = argparse.ArgumentParser(
        description="Team Cymru IP-to-ASN client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --ip 8.8.8.8                       Single IP lookup
  %(prog)s --ip 2001:4860:4860::8888          IPv6 lookup
  %(prog)s --bulk-ips 8.8.8.8 1.1.1.1 9.9.9.9  Bulk via whois
  %(prog)s --prefix 1.1.1.0/24                Prefix to ASN
  %(prog)s --asn 13335                        ASN name lookup
  %(prog)s --bulk-file ips.txt                Bulk from file
""")
    parser.add_argument("--ip", help="Single IP to ASN lookup (DNS)")
    parser.add_argument("--bulk-ips", nargs="+", help="Multiple IPs (whois bulk)")
    parser.add_argument("--prefix", help="Prefix to ASN")
    parser.add_argument("--asn", help="ASN name lookup")
    parser.add_argument("--bulk-file", help="File with one IP per line")
    parser.add_argument("--raw-json", action="store_true", help="JSON output")
    args = parser.parse_args()
    client = TeamCymru()

    if args.ip:
        result = client.ip_to_asn_dns(args.ip)
        if args.raw_json:
            print(json.dumps(result, indent=2))
        else:
            print("IP: {}".format(args.ip))
            for k, v in result.items():
                if k != "raw":
                    print("  {}: {}".format(k, v))

    elif args.bulk_ips:
        results = client.bulk_whois(args.bulk_ips)
        if args.raw_json:
            print(json.dumps(results, indent=2))
            return
        print("{:<18} {:<8} {:<20} {:<4} {}".format("IP", "ASN", "Prefix", "CC", "AS Name"))
        print("-" * 75)
        for r in results:
            print("{:<18} {:<8} {:<20} {:<4} {}".format(
                r.get("ip", ""), r.get("asn", ""), r.get("prefix", ""),
                r.get("cc", ""), r.get("as_name", "")))

    elif args.prefix:
        result = client.prefix_to_asn(args.prefix)
        if args.raw_json:
            print(json.dumps(result, indent=2))
        else:
            print("Prefix: {}".format(args.prefix))
            for k, v in result.items():
                if k != "raw":
                    print("  {}: {}".format(k, v))

    elif args.asn:
        result = client.asn_name_dns(args.asn)
        if args.raw_json:
            print(json.dumps(result, indent=2))
        else:
            print("ASN: {}".format(args.asn))
            for k, v in result.items():
                if k != "raw":
                    print("  {}: {}".format(k, v))

    elif args.bulk_file:
        with open(args.bulk_file) as f:
            ips = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        results = client.bulk_whois(ips)
        if args.raw_json:
            print(json.dumps(results, indent=2))
            return
        print("{:<18} {:<8} {:<20} {:<4} {}".format("IP", "ASN", "Prefix", "CC", "AS Name"))
        print("-" * 75)
        for r in results:
            print("{:<18} {:<8} {:<20} {:<4} {}".format(
                r.get("ip", ""), r.get("asn", ""), r.get("prefix", ""),
                r.get("cc", ""), r.get("as_name", "")))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
