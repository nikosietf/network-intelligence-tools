#!/usr/bin/env python3
"""
BGPView API Client — ASN, prefix, IP, and IX lookups.

A Python client for the BGPView API, providing access to ASN information,
prefix announcements, peer relationships, and IX participation data.

No API key required. Rate limit: ~30 req/min.

Usage:
    python3 bgpview_client.py --asn 13335
    python3 bgpview_client.py --asn-prefixes 13335
    python3 bgpview_client.py --prefix 1.1.1.0/24
    python3 bgpview_client.py --ip 1.1.1.1

Author: Nikos Leontsinis
License: MIT
"""

import argparse
import json
import sys
import requests

BASE_URL = "https://api.bgpview.io"


class BGPView:
    def __init__(self, timeout=30):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json"})

    def _get(self, path, params=None):
        resp = self.session.get("{}/{}".format(BASE_URL, path), params=params, timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()
        return data.get("data", {}) if data.get("status") == "ok" else data

    def asn(self, asn):
        return self._get("asn/{}".format(asn))

    def asn_prefixes(self, asn):
        return self._get("asn/{}/prefixes".format(asn))

    def asn_peers(self, asn):
        return self._get("asn/{}/peers".format(asn))

    def asn_upstreams(self, asn):
        return self._get("asn/{}/upstreams".format(asn))

    def asn_downstreams(self, asn):
        return self._get("asn/{}/downstreams".format(asn))

    def asn_ixs(self, asn):
        return self._get("asn/{}/ixs".format(asn))

    def prefix(self, prefix):
        return self._get("prefix/{}".format(prefix))

    def ip(self, ip_addr):
        return self._get("ip/{}".format(ip_addr))

    def ix(self, ix_id):
        return self._get("ix/{}".format(ix_id))

    def search(self, query):
        return self._get("search", {"query_term": query})


def main():
    parser = argparse.ArgumentParser(
        description="BGPView API client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --asn 13335
  %(prog)s --asn-prefixes 13335
  %(prog)s --asn-peers 13335
  %(prog)s --asn-upstreams 13335
  %(prog)s --asn-downstreams 13335
  %(prog)s --asn-ixs 13335
  %(prog)s --prefix 1.1.1.0/24
  %(prog)s --ip 1.1.1.1
  %(prog)s --ix 1
  %(prog)s --search Cloudflare
""")
    parser.add_argument("--asn", type=int)
    parser.add_argument("--asn-prefixes", type=int)
    parser.add_argument("--asn-peers", type=int)
    parser.add_argument("--asn-upstreams", type=int)
    parser.add_argument("--asn-downstreams", type=int)
    parser.add_argument("--asn-ixs", type=int)
    parser.add_argument("--prefix")
    parser.add_argument("--ip")
    parser.add_argument("--ix", type=int)
    parser.add_argument("--search")
    parser.add_argument("--raw-json", action="store_true")
    args = parser.parse_args()
    client = BGPView()
    result = None

    if args.asn:
        result = client.asn(args.asn)
        if not args.raw_json:
            print("=== AS{} ===".format(args.asn))
            for k in ["name", "description_short", "website", "looking_glass", "traffic_estimation", "traffic_ratio"]:
                if result.get(k):
                    print("  {}: {}".format(k, result[k]))

    elif args.asn_prefixes:
        result = client.asn_prefixes(args.asn_prefixes)
        if not args.raw_json:
            v4, v6 = result.get("ipv4_prefixes", []), result.get("ipv6_prefixes", [])
            print("=== Prefixes AS{} ({} v4, {} v6) ===".format(args.asn_prefixes, len(v4), len(v6)))
            for p in v4:
                print("  {:<20} {}".format(p.get("prefix", ""), p.get("description", "")))
            for p in v6:
                print("  {:<44} {}".format(p.get("prefix", ""), p.get("description", "")))

    elif args.asn_peers:
        result = client.asn_peers(args.asn_peers)
        if not args.raw_json:
            all_p = {p["asn"]: p for p in result.get("ipv4_peers", []) + result.get("ipv6_peers", [])}
            print("=== Peers AS{} ({} unique) ===".format(args.asn_peers, len(all_p)))
            for p in sorted(all_p.values(), key=lambda x: x.get("asn", 0)):
                print("  AS{:<8} {}".format(p.get("asn", ""), p.get("name", "")))

    elif args.asn_upstreams:
        result = client.asn_upstreams(args.asn_upstreams)
        if not args.raw_json:
            ups = {p["asn"]: p for p in result.get("ipv4_upstreams", []) + result.get("ipv6_upstreams", [])}
            print("=== Upstreams AS{} ({}) ===".format(args.asn_upstreams, len(ups)))
            for p in sorted(ups.values(), key=lambda x: x.get("asn", 0)):
                print("  AS{:<8} {}".format(p.get("asn", ""), p.get("name", "")))

    elif args.asn_downstreams:
        result = client.asn_downstreams(args.asn_downstreams)
        if not args.raw_json:
            downs = {p["asn"]: p for p in result.get("ipv4_downstreams", []) + result.get("ipv6_downstreams", [])}
            print("=== Downstreams AS{} ({}) ===".format(args.asn_downstreams, len(downs)))
            for p in sorted(downs.values(), key=lambda x: x.get("asn", 0)):
                print("  AS{:<8} {}".format(p.get("asn", ""), p.get("name", "")))

    elif args.asn_ixs:
        result = client.asn_ixs(args.asn_ixs)
        if not args.raw_json:
            print("=== IXs for AS{} ({}) ===".format(args.asn_ixs, len(result)))
            for ix in sorted(result, key=lambda x: x.get("name", "")):
                print("  {:<35} {} v4={} v6={}".format(
                    ix.get("name", "")[:34], ix.get("country_code", ""),
                    ix.get("ipv4_address", "-"), ix.get("ipv6_address", "-")))

    elif args.prefix:
        result = client.prefix(args.prefix)
        if not args.raw_json:
            print("=== {} ===".format(args.prefix))
            for a in result.get("asns", []):
                print("  Origin: AS{} - {}".format(a.get("asn", ""), a.get("name", "")))

    elif args.ip:
        result = client.ip(args.ip)
        if not args.raw_json:
            print("=== {} ===".format(args.ip))
            print("  PTR: {}".format(result.get("ptr_record", "")))
            for p in result.get("prefixes", []):
                print("  Prefix: {} (AS{})".format(p.get("prefix", ""), p.get("asn", {}).get("asn", "")))

    elif args.ix:
        result = client.ix(args.ix)
        if not args.raw_json:
            print("=== IX {} — {} ===".format(args.ix, result.get("name", "")))
            print("  City: {}, {}".format(result.get("city", ""), result.get("country_code", "")))
            print("  Members: {}".format(result.get("members_count", "")))

    elif args.search:
        result = client.search(args.search)
        if not args.raw_json:
            for a in result.get("asns", [])[:20]:
                print("  AS{:<8} {}".format(a.get("asn", ""), a.get("name", "")))

    else:
        parser.print_help()
        return

    if args.raw_json and result:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
