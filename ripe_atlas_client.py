#!/usr/bin/env python3
"""
RIPE Atlas API Client — Measurements, probes, and anchors.

A Python client for the RIPE Atlas API, enabling network measurements
(traceroute, ping, DNS) from thousands of globally distributed probes.

Read-only queries don't need an API key. Creating measurements does.

Usage:
    python3 ripe_atlas_client.py --probes-in GB
    python3 ripe_atlas_client.py --probes-for-asn 13335
    python3 ripe_atlas_client.py --anchors
    python3 ripe_atlas_client.py --measurement 1001
    python3 ripe_atlas_client.py --traceroute-to 1.1.1.1 --from-country GB
    python3 ripe_atlas_client.py --dns-to google.com --from-asn 13335

Author: Nikos Leontsinis
License: MIT
"""

import argparse
import json
import sys
import os
import requests

BASE_URL = "https://atlas.ripe.net/api/v2"


class RIPEAtlas:
    def __init__(self, api_key=None, timeout=30):
        self.timeout = timeout
        self.api_key = api_key or os.environ.get("RIPE_ATLAS_KEY", "")
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json"})
        if self.api_key:
            self.session.headers.update({"Authorization": "Key {}".format(self.api_key)})

    def _get(self, path, params=None):
        resp = self.session.get("{}/{}".format(BASE_URL, path), params=params, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    # --- Probes ---
    def probes(self, **kwargs):
        """List probes. Filters: country_code, asn_v4, status, is_anchor, etc."""
        return self._get("probes/", params=kwargs)

    def probe(self, probe_id):
        """Get single probe details."""
        return self._get("probes/{}/".format(probe_id))

    def probes_by_country(self, country):
        """List probes in a country."""
        return self._get("probes/", params={"country_code": country, "status": 1, "page_size": 100})

    def probes_by_asn(self, asn):
        """List probes in an ASN."""
        return self._get("probes/", params={"asn_v4": asn, "status": 1, "page_size": 100})

    # --- Anchors ---
    def anchors(self, **kwargs):
        """List anchors."""
        return self._get("anchors/", params=kwargs)

    # --- Measurements ---
    def measurement(self, msm_id):
        """Get measurement metadata."""
        return self._get("measurements/{}/".format(msm_id))

    def measurement_results(self, msm_id, **kwargs):
        """Get measurement results."""
        return self._get("measurements/{}/results/".format(msm_id), params=kwargs)

    def measurements_list(self, **kwargs):
        """List measurements. Filters: target, type, af, status, etc."""
        return self._get("measurements/", params=kwargs)

    # --- Credits ---
    def credits(self):
        """Check your credit balance (needs API key)."""
        return self._get("credits/")

    # --- Create measurements (needs API key) ---
    def create_measurement(self, definitions, probes, is_oneoff=True):
        """Create a measurement. Returns measurement IDs."""
        payload = {
            "definitions": definitions,
            "probes": probes,
            "is_oneoff": is_oneoff,
        }
        resp = self.session.post("{}/measurements/".format(BASE_URL), json=payload, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def create_traceroute(self, target, from_country=None, from_asn=None, probe_count=10, af=4):
        """Create a one-off traceroute measurement."""
        definitions = [{"type": "traceroute", "af": af, "target": target, "protocol": "ICMP",
                        "resolve_on_probe": True, "description": "traceroute to {}".format(target)}]
        probes_spec = [{"requested": probe_count, "type": "area", "value": "WW"}]
        if from_country:
            probes_spec = [{"requested": probe_count, "type": "country", "value": from_country}]
        elif from_asn:
            probes_spec = [{"requested": probe_count, "type": "asn", "value": int(str(from_asn).replace("AS", ""))}]
        return self.create_measurement(definitions, probes_spec)

    def create_ping(self, target, from_country=None, from_asn=None, probe_count=10, af=4):
        """Create a one-off ping measurement."""
        definitions = [{"type": "ping", "af": af, "target": target, "packets": 3,
                        "description": "ping to {}".format(target)}]
        probes_spec = [{"requested": probe_count, "type": "area", "value": "WW"}]
        if from_country:
            probes_spec = [{"requested": probe_count, "type": "country", "value": from_country}]
        elif from_asn:
            probes_spec = [{"requested": probe_count, "type": "asn", "value": int(str(from_asn).replace("AS", ""))}]
        return self.create_measurement(definitions, probes_spec)

    def create_dns(self, target, query_type="A", from_country=None, from_asn=None, probe_count=10, af=4):
        """Create a one-off DNS measurement."""
        definitions = [{"type": "dns", "af": af, "target": target,
                        "query_class": "IN", "query_type": query_type, "use_macros": False,
                        "query_argument": target, "description": "DNS {} {}".format(query_type, target)}]
        probes_spec = [{"requested": probe_count, "type": "area", "value": "WW"}]
        if from_country:
            probes_spec = [{"requested": probe_count, "type": "country", "value": from_country}]
        elif from_asn:
            probes_spec = [{"requested": probe_count, "type": "asn", "value": int(str(from_asn).replace("AS", ""))}]
        return self.create_measurement(definitions, probes_spec)


def main():
    parser = argparse.ArgumentParser(
        description="RIPE Atlas API client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --probes-in GB                        Probes in Great Britain
  %(prog)s --probes-for-asn 13335                Probes in AS13335
  %(prog)s --anchors                             List all anchors
  %(prog)s --measurement 1001                    Measurement details
  %(prog)s --measurement-results 1001            Measurement results
  %(prog)s --traceroute-to 1.1.1.1 --from-country GB --count 5
  %(prog)s --ping-to 8.8.8.8 --from-asn 13335
  %(prog)s --dns-to google.com --from-country US
  %(prog)s --credits                             Check credit balance
""")
    parser.add_argument("--probes-in", help="List probes in country (2-letter code)")
    parser.add_argument("--probes-for-asn", type=int, help="List probes in ASN")
    parser.add_argument("--anchors", action="store_true", help="List anchors")
    parser.add_argument("--measurement", type=int, help="Get measurement details")
    parser.add_argument("--measurement-results", type=int, help="Get measurement results")
    parser.add_argument("--traceroute-to", help="Create traceroute to target")
    parser.add_argument("--ping-to", help="Create ping to target")
    parser.add_argument("--dns-to", help="Create DNS query for target")
    parser.add_argument("--from-country", help="Source probes from country")
    parser.add_argument("--from-asn", help="Source probes from ASN")
    parser.add_argument("--count", type=int, default=10, help="Number of probes")
    parser.add_argument("--credits", action="store_true", help="Check credits")
    parser.add_argument("--raw-json", action="store_true", help="Raw JSON")
    args = parser.parse_args()
    client = RIPEAtlas()

    if args.probes_in:
        result = client.probes_by_country(args.probes_in)
        probes = result.get("results", [])
        if args.raw_json:
            print(json.dumps(result, indent=2))
            return
        print("=== Probes in {} ({} found) ===".format(args.probes_in, result.get("count", len(probes))))
        for p in probes[:30]:
            print("  #{:<6} AS{:<8} {} ({}, {})".format(p.get("id", ""), p.get("asn_v4", ""),
                p.get("address_v4", ""), p.get("city", "") or "?", p.get("country_code", "")))

    elif args.probes_for_asn:
        result = client.probes_by_asn(args.probes_for_asn)
        probes = result.get("results", [])
        if args.raw_json:
            print(json.dumps(result, indent=2))
            return
        print("=== Probes in AS{} ({} found) ===".format(args.probes_for_asn, result.get("count", len(probes))))
        for p in probes[:30]:
            print("  #{:<6} {} ({})".format(p.get("id", ""), p.get("address_v4", ""), p.get("city", "") or "?"))

    elif args.anchors:
        result = client.anchors()
        anchors = result.get("results", [])
        if args.raw_json:
            print(json.dumps(result, indent=2))
            return
        print("=== Anchors ({}) ===".format(result.get("count", len(anchors))))
        for a in anchors[:30]:
            print("  #{:<6} {} ({}, AS{})".format(a.get("id", ""), a.get("fqdn", ""), a.get("country", ""), a.get("as_v4", "")))

    elif args.measurement:
        result = client.measurement(args.measurement)
        if args.raw_json:
            print(json.dumps(result, indent=2))
            return
        print("=== Measurement {} ===".format(args.measurement))
        for k in ["type", "target", "description", "af", "status", "creation_time", "probes_requested", "probes_scheduled"]:
            if result.get(k) is not None:
                print("  {}: {}".format(k, result[k]))

    elif args.measurement_results:
        result = client.measurement_results(args.measurement_results)
        if args.raw_json:
            print(json.dumps(result, indent=2))
            return
        if isinstance(result, list):
            print("=== Results for {} ({} entries) ===".format(args.measurement_results, len(result)))
            for r in result[:10]:
                src = r.get("from", "")
                dst = r.get("dst_addr", "")
                rtt = r.get("avg", "") or r.get("result", {})
                print("  {} -> {} : {}".format(src, dst, rtt))

    elif args.traceroute_to:
        result = client.create_traceroute(args.traceroute_to, from_country=args.from_country,
                                          from_asn=args.from_asn, probe_count=args.count)
        print("Measurement created: {}".format(result))

    elif args.ping_to:
        result = client.create_ping(args.ping_to, from_country=args.from_country,
                                    from_asn=args.from_asn, probe_count=args.count)
        print("Measurement created: {}".format(result))

    elif args.dns_to:
        result = client.create_dns(args.dns_to, from_country=args.from_country,
                                   from_asn=args.from_asn, probe_count=args.count)
        print("Measurement created: {}".format(result))

    elif args.credits:
        result = client.credits()
        if args.raw_json:
            print(json.dumps(result, indent=2))
            return
        print("Credits: {}".format(result))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
