#!/usr/bin/env python3
"""
Cloudflare Radar API Client — BGP, routing, traffic anomalies.

A Python client for the Cloudflare Radar API, providing access to BGP routing
data, route leaks, hijacks, AS relationships, and internet quality metrics.

Requires free API key from https://dash.cloudflare.com/profile/api-tokens
Set env: CLOUDFLARE_API_TOKEN or CLOUDFLARE_API_KEY + CLOUDFLARE_EMAIL

Usage:
    python3 cloudflare_radar_client.py --bgp-routes AS13335
    python3 cloudflare_radar_client.py --bgp-leaks
    python3 cloudflare_radar_client.py --bgp-hijacks
    python3 cloudflare_radar_client.py --asn-overview 13335

Author: Nikos Leontsinis
License: MIT
"""

import argparse
import json
import os
import sys
import requests
from datetime import datetime, timedelta

BASE_URL = "https://api.cloudflare.com/client/v4/radar"


class CloudflareRadar:
    def __init__(self, timeout=30):
        self.timeout = timeout
        self.session = requests.Session()
        token = os.environ.get("CLOUDFLARE_API_TOKEN", "")
        if token:
            self.session.headers.update({"Authorization": "Bearer {}".format(token)})
        else:
            key = os.environ.get("CLOUDFLARE_API_KEY", "")
            email = os.environ.get("CLOUDFLARE_EMAIL", "")
            if key and email:
                self.session.headers.update({"X-Auth-Key": key, "X-Auth-Email": email})
        self.session.headers.update({"Content-Type": "application/json"})

    def _get(self, path, params=None):
        resp = self.session.get("{}/{}".format(BASE_URL, path), params=params, timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()
        return data.get("result", data)

    # --- BGP ---
    def bgp_routes(self, asn=None, prefix=None, **kwargs):
        """Get BGP routes for ASN or prefix."""
        params = {**kwargs}
        if asn:
            params["origin"] = int(str(asn).replace("AS", ""))
        if prefix:
            params["prefix"] = prefix
        return self._get("bgp/routes", params)

    def bgp_route_leaks(self, **kwargs):
        """Get recent BGP route leak events."""
        params = {"per_page": 25, **kwargs}
        return self._get("bgp/leaks/events", params)

    def bgp_hijacks(self, **kwargs):
        """Get recent BGP hijack events."""
        params = {"per_page": 25, **kwargs}
        return self._get("bgp/hijacks/events", params)

    def bgp_top_ases(self, **kwargs):
        """Top ASes by prefix count."""
        return self._get("bgp/top/ases", params=kwargs)

    def bgp_top_prefixes(self, **kwargs):
        """Top prefixes."""
        return self._get("bgp/top/prefixes", params=kwargs)

    def bgp_timeseries(self, asn=None, **kwargs):
        """BGP route count timeseries."""
        params = {**kwargs}
        if asn:
            params["asn"] = int(str(asn).replace("AS", ""))
        return self._get("bgp/timeseries", params)

    # --- AS ---
    def as_overview(self, asn):
        """Get AS overview from Cloudflare's perspective."""
        asn_num = int(str(asn).replace("AS", ""))
        return self._get("entities/asns/{}".format(asn_num))

    def as_relationships(self, asn):
        """Get AS relationships (peers, upstreams, downstreams)."""
        asn_num = int(str(asn).replace("AS", ""))
        return self._get("entities/asns/{}/rel".format(asn_num))

    # --- Traffic / Internet quality ---
    def traffic_top_locations(self, **kwargs):
        """Top traffic locations."""
        return self._get("http/top/locations", params=kwargs)

    def traffic_top_ases(self, **kwargs):
        """Top ASes by traffic."""
        return self._get("http/top/ases", params=kwargs)

    def internet_quality(self, asn=None, location=None, **kwargs):
        """Internet quality metrics (latency, jitter, bandwidth)."""
        params = {**kwargs}
        if asn:
            params["asn"] = int(str(asn).replace("AS", ""))
        if location:
            params["location"] = location
        return self._get("quality/speed/summary", params)

    # --- Attacks ---
    def attacks_layer3_top(self, **kwargs):
        """Top L3/L4 DDoS attack targets."""
        return self._get("attacks/layer3/top/locations/target", params=kwargs)

    def attacks_layer7_top(self, **kwargs):
        """Top L7 attack targets."""
        return self._get("attacks/layer7/top/locations/target", params=kwargs)

    # --- Routing anomalies ---
    def routing_moas(self, **kwargs):
        """Multi-Origin AS (MOAS) conflicts."""
        params = {"per_page": 25, **kwargs}
        return self._get("bgp/routes/moas", params)

    def routing_stats(self, asn=None, **kwargs):
        """Routing stats for an ASN."""
        params = {**kwargs}
        if asn:
            params["asn"] = int(str(asn).replace("AS", ""))
        return self._get("bgp/routes/stats", params)


def main():
    parser = argparse.ArgumentParser(
        description="Cloudflare Radar API client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --bgp-routes AS13335
  %(prog)s --bgp-routes-prefix 1.1.1.0/24
  %(prog)s --bgp-leaks
  %(prog)s --bgp-hijacks
  %(prog)s --bgp-timeseries AS13335
  %(prog)s --routing-stats AS13335
  %(prog)s --asn-overview 13335
  %(prog)s --as-relationships 13335
  %(prog)s --top-ases
  %(prog)s --internet-quality AS13335

Env vars: CLOUDFLARE_API_TOKEN (Bearer token)
""")
    parser.add_argument("--bgp-routes", help="BGP routes for ASN")
    parser.add_argument("--bgp-routes-prefix", help="BGP routes for prefix")
    parser.add_argument("--bgp-leaks", action="store_true", help="Recent BGP leaks")
    parser.add_argument("--bgp-hijacks", action="store_true", help="Recent BGP hijacks")
    parser.add_argument("--bgp-timeseries", help="Route count timeseries for ASN")
    parser.add_argument("--routing-stats", help="Routing stats for ASN")
    parser.add_argument("--asn-overview", help="AS overview")
    parser.add_argument("--as-relationships", help="AS relationships")
    parser.add_argument("--top-ases", action="store_true", help="Top ASes")
    parser.add_argument("--internet-quality", help="Internet quality for ASN")
    parser.add_argument("--raw-json", action="store_true", help="Raw JSON")
    args = parser.parse_args()
    client = CloudflareRadar()

    result = None
    if args.bgp_routes:
        result = client.bgp_routes(asn=args.bgp_routes)
    elif args.bgp_routes_prefix:
        result = client.bgp_routes(prefix=args.bgp_routes_prefix)
    elif args.bgp_leaks:
        result = client.bgp_route_leaks()
    elif args.bgp_hijacks:
        result = client.bgp_hijacks()
    elif args.bgp_timeseries:
        result = client.bgp_timeseries(asn=args.bgp_timeseries)
    elif args.routing_stats:
        result = client.routing_stats(asn=args.routing_stats)
    elif args.asn_overview:
        result = client.as_overview(args.asn_overview)
    elif args.as_relationships:
        result = client.as_relationships(args.as_relationships)
    elif args.top_ases:
        result = client.bgp_top_ases()
    elif args.internet_quality:
        result = client.internet_quality(asn=args.internet_quality)
    else:
        parser.print_help()
        return

    if result:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
