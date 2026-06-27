#!/usr/bin/env python3
"""
IRRexplorer API Client — IRR/RPKI/BGP cross-validation.

A Python client for the IRRexplorer API, providing IRR database validation,
RPKI status checking, and BGP origin verification.

No API key required.

Usage:
    python3 irrexplorer_client.py --asn 13335
    python3 irrexplorer_client.py --prefix 1.1.1.0/24

Author: Nikos Leontsinis
License: MIT
"""

import argparse
import json
import sys
import requests

BASE_URL = "https://irrexplorer.nlnog.net/api"


class IRRexplorer:
    def __init__(self, timeout=60):
        self.timeout = timeout
        self.session = requests.Session()

    def _get(self, path, params=None):
        resp = self.session.get("{}/{}".format(BASE_URL, path), params=params, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def prefix_info(self, prefix):
        """Get IRR/BGP/RPKI status for a prefix."""
        return self._get("prefixes/prefix/{}".format(prefix))

    def asn_prefixes(self, asn):
        """Get all prefixes for an ASN with IRR/BGP/RPKI cross-validation.
        Returns dict with 'directOrigin' and 'overlaps' lists."""
        asn_num = str(asn).replace("AS", "").replace("as", "")
        return self._get("prefixes/asn/AS{}".format(asn_num))

    def asn_sets(self, asset):
        """Resolve an AS-SET to member ASNs."""
        return self._get("sets/member-of/{}".format(asset))


def main():
    parser = argparse.ArgumentParser(
        description="IRRexplorer API client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --asn 13335
  %(prog)s --prefix 1.1.1.0/24
  %(prog)s --as-set AS-CLOUDFLARE
  %(prog)s --asn 13335 --problems-only
""")
    parser.add_argument("--asn", help="ASN to check (e.g. 13335 or AS13335)")
    parser.add_argument("--prefix", help="Prefix to check")
    parser.add_argument("--as-set", help="AS-SET to resolve")
    parser.add_argument("--problems-only", action="store_true", help="Only show prefixes with issues")
    parser.add_argument("--include-overlaps", action="store_true", help="Include overlapping prefixes")
    parser.add_argument("--raw-json", action="store_true", help="Raw JSON output")
    args = parser.parse_args()
    client = IRRexplorer()

    if args.asn:
        data = client.asn_prefixes(args.asn)
        if args.raw_json:
            print(json.dumps(data, indent=2))
            return

        direct = data.get("directOrigin", [])
        overlaps = data.get("overlaps", [])

        # Categorize direct origins
        ok, problems = [], []
        for entry in direct:
            cat = entry.get("categoryOverall", "")
            if cat in ("success", "info"):
                if not args.problems_only:
                    ok.append(entry)
            else:
                problems.append(entry)

        asn_str = args.asn.replace("AS", "").replace("as", "")
        print("=== IRRexplorer: AS{} ===".format(asn_str))
        print("  Direct origin prefixes: {}".format(len(direct)))
        print("  Overlapping prefixes:   {}".format(len(overlaps)))
        print("  OK: {}".format(len(direct) - len(problems)))
        print("  Problems: {}".format(len(problems)))
        print()

        if problems:
            print("--- PROBLEMS ({}) ---".format(len(problems)))
            print("{:<22} {:<12} {:<12} {:<10} {}".format("Prefix", "Category", "BGP Origins", "RPKI", "Messages"))
            print("-" * 90)
            for entry in sorted(problems, key=lambda x: x.get("prefix", "")):
                pfx = entry.get("prefix", "")
                cat = entry.get("categoryOverall", "")
                bgp = ",".join(["AS{}".format(a) for a in entry.get("bgpOrigins", [])])
                rpki = entry.get("rpkiRoutes", [])
                rpki_status = "valid" if rpki else "none"
                msgs = "; ".join([m.get("text", "") for m in entry.get("messages", [])])
                print("{:<22} {:<12} {:<12} {:<10} {}".format(pfx, cat, bgp[:11], rpki_status[:9], msgs[:50]))

        if not args.problems_only and ok:
            print("\n--- OK ({}) ---".format(len(ok)))
            for entry in sorted(ok, key=lambda x: x.get("prefix", ""))[:30]:
                pfx = entry.get("prefix", "")
                cat = entry.get("categoryOverall", "")
                bgp = ",".join(["AS{}".format(a) for a in entry.get("bgpOrigins", [])])
                print("  {:<22} [{}] BGP:{}".format(pfx, cat, bgp[:20]))
            if len(ok) > 30:
                print("  ... and {} more".format(len(ok) - 30))

        if args.include_overlaps and overlaps:
            print("\n--- OVERLAPS ({}) ---".format(len(overlaps)))
            for entry in sorted(overlaps, key=lambda x: x.get("prefix", ""))[:20]:
                pfx = entry.get("prefix", "")
                cat = entry.get("categoryOverall", "")
                bgp = ",".join(["AS{}".format(a) for a in entry.get("bgpOrigins", [])])
                print("  {:<22} [{}] BGP:{}".format(pfx, cat, bgp[:20]))

    elif args.prefix:
        result = client.prefix_info(args.prefix)
        if args.raw_json:
            print(json.dumps(result, indent=2))
            return
        print("=== IRRexplorer: {} ===".format(args.prefix))
        # prefix_info returns a list
        entries = result if isinstance(result, list) else [result]
        for entry in entries:
            if isinstance(entry, dict):
                print("  Category: {}".format(entry.get("categoryOverall", "")))
                print("  BGP Origins: {}".format(entry.get("bgpOrigins", [])))
                print("  RIR: {}".format(entry.get("rir", "")))
                irr = entry.get("irrRoutes", {})
                for db, routes in irr.items():
                    for r in routes:
                        print("  IRR [{}]: AS{} - {}".format(db, r.get("asn", ""), r.get("rpslText", "")[:80]))
                rpki = entry.get("rpkiRoutes", [])
                for r in rpki:
                    print("  RPKI: AS{} valid".format(r.get("asn", "")))
                for m in entry.get("messages", []):
                    print("  MSG [{}]: {}".format(m.get("category", ""), m.get("text", "")))
                print()

    elif args.as_set:
        result = client.asn_sets(args.as_set)
        if args.raw_json:
            print(json.dumps(result, indent=2))
            return
        print("=== AS-SET: {} ===".format(args.as_set))
        if isinstance(result, list):
            print("  Members: {}".format(len(result)))
            for member in result[:50]:
                print("  {}".format(member))
            if len(result) > 50:
                print("  ... and {} more".format(len(result) - 50))
        else:
            print(json.dumps(result, indent=2))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
