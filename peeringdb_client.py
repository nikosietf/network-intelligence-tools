#!/usr/bin/env python3
"""
PeeringDB API Client — Full network/IX/facility intelligence.

A comprehensive Python client for the PeeringDB REST API, providing access to
network information, IX presence, facility data, and peering contacts.

Usage:
    python3 peeringdb_client.py --asn 13335
    python3 peeringdb_client.py --ix-id 1       # AMS-IX
    python3 peeringdb_client.py --facility 1
    python3 peeringdb_client.py --search "Cloudflare"
    python3 peeringdb_client.py --exchanges-for-asn 13335

No API key required for read-only access.

Author: Nikos Leontsinis
License: MIT
"""

import argparse
import json
import sys
import time
import requests

BASE_URL = "https://www.peeringdb.com/api"


class PeeringDB:
    """Client for PeeringDB REST API."""

    def __init__(self, timeout=30):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json"})

    def _get(self, endpoint, params=None):
        url = f"{BASE_URL}/{endpoint}"
        resp = self.session.get(url, params=params, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json().get("data", [])

    # --- Network (net) ---
    def network_by_asn(self, asn):
        """Get network record by ASN."""
        return self._get("net", {"asn": asn})

    def network_by_id(self, net_id):
        """Get network by PeeringDB network ID."""
        return self._get(f"net/{net_id}")

    def network_search(self, name):
        """Search networks by name."""
        return self._get("net", {"name__contains": name})

    # --- Internet Exchange (ix) ---
    def ix_by_id(self, ix_id):
        """Get IX details by ID."""
        return self._get(f"ix/{ix_id}")

    def ix_search(self, name):
        """Search IXs by name."""
        return self._get("ix", {"name__contains": name})

    def ix_list_all(self):
        """List all IXs."""
        return self._get("ix")

    # --- IX LAN (ixlan) ---
    def ixlan_by_ix(self, ix_id):
        """Get IX LAN details (prefix info)."""
        return self._get("ixlan", {"ix_id": ix_id})

    # --- IX LAN Prefix (ixpfx) ---
    def ixlan_prefixes(self, ixlan_id):
        """Get peering LAN prefixes."""
        return self._get("ixpfx", {"ixlan_id": ixlan_id})

    # --- Network IX LAN (netixlan) — peering sessions ---
    def network_ixlan(self, asn=None, ix_id=None, net_id=None):
        """Get peering sessions (network presence at IXs)."""
        params = {}
        if asn:
            params["asn"] = asn
        if ix_id:
            params["ix_id"] = ix_id
        if net_id:
            params["net_id"] = net_id
        return self._get("netixlan", params)

    # --- Facility (fac) ---
    def facility_by_id(self, fac_id):
        """Get facility details."""
        return self._get(f"fac/{fac_id}")

    def facility_search(self, name):
        """Search facilities by name."""
        return self._get("fac", {"name__contains": name})

    def facilities_in_city(self, city):
        """Find facilities in a city."""
        return self._get("fac", {"city__contains": city})

    def facilities_in_country(self, country):
        """Find facilities in a country (2-letter code)."""
        return self._get("fac", {"country": country})

    # --- Network Facility (netfac) — physical presence ---
    def network_facilities(self, asn=None, net_id=None, fac_id=None):
        """Get network's physical facility presence."""
        params = {}
        if asn:
            params["asn"] = asn  # not directly supported, use net_id
        if net_id:
            params["net_id"] = net_id
        if fac_id:
            params["fac_id"] = fac_id
        return self._get("netfac", params)

    # --- Network Contact (poc) ---
    def network_contacts(self, net_id):
        """Get network's contact info (NOC, policy, etc.)."""
        return self._get("poc", {"net_id": net_id})

    # --- Carrier (carrier) ---
    def carrier_search(self, name):
        """Search carriers."""
        return self._get("carrier", {"name__contains": name})

    # --- Campus ---
    def campus_search(self, name):
        """Search campus."""
        return self._get("campus", {"name__contains": name})

    # --- High-level helpers ---
    def get_full_network_info(self, asn):
        """Get comprehensive info: network + IX presence + facilities."""
        nets = self.network_by_asn(asn)
        if not nets:
            return None
        net = nets[0]
        net_id = net["id"]

        # IX presence (peering sessions)
        ixlans = self.network_ixlan(net_id=net_id)

        # Facility presence
        netfacs = self.network_facilities(net_id=net_id)

        # Contacts
        contacts = self.network_contacts(net_id)

        return {
            "network": net,
            "ix_presence": ixlans,
            "facilities": netfacs,
            "contacts": contacts,
        }

    def get_exchanges_for_asn(self, asn):
        """List all IXs where an ASN is present with peering details."""
        nets = self.network_by_asn(asn)
        if not nets:
            return []
        net_id = nets[0]["id"]
        ixlans = self.network_ixlan(net_id=net_id)

        # Group by IX
        ix_map = {}
        for entry in ixlans:
            ix_name = entry.get("name", "Unknown IX")
            ix_id = entry.get("ix_id", "")
            if ix_name not in ix_map:
                ix_map[ix_name] = {
                    "ix_id": ix_id,
                    "ix_name": ix_name,
                    "sessions": []
                }
            ix_map[ix_name]["sessions"].append({
                "ipaddr4": entry.get("ipaddr4", ""),
                "ipaddr6": entry.get("ipaddr6", ""),
                "speed": entry.get("speed", 0),
                "is_rs_peer": entry.get("is_rs_peer", False),
            })
        return list(ix_map.values())

    def get_peers_at_ix(self, ix_id):
        """List all networks peering at a specific IX."""
        return self.network_ixlan(ix_id=ix_id)


def format_speed(speed_mbps):
    """Format speed in Mbps to human readable."""
    if speed_mbps >= 1000000:
        return "{}T".format(speed_mbps // 1000000)
    elif speed_mbps >= 1000:
        return "{}G".format(speed_mbps // 1000)
    return "{}M".format(speed_mbps)


def main():
    parser = argparse.ArgumentParser(
        description="PeeringDB API client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --asn 13335                        Full network info for Cloudflare
  %(prog)s --exchanges-for-asn 13335          IXs where AS13335 peers
  %(prog)s --peers-at-ix 1                    All peers at AMS-IX
  %(prog)s --search "Cloudflare"              Search networks by name
  %(prog)s --ix-search "AMS-IX"              Search IXs
  %(prog)s --facility-search "Equinix AM"    Search facilities
  %(prog)s --facilities-in Amsterdam          Facilities in a city
  %(prog)s --asn 13335 --raw-json            Raw JSON output
""")
    parser.add_argument("--asn", type=int, help="Network ASN to query")
    parser.add_argument("--exchanges-for-asn", type=int, help="List IXs for ASN")
    parser.add_argument("--peers-at-ix", type=int, help="List peers at IX (by IX ID)")
    parser.add_argument("--ix-id", type=int, help="Get IX details by ID")
    parser.add_argument("--ix-search", help="Search IXs by name")
    parser.add_argument("--facility-search", help="Search facilities")
    parser.add_argument("--facilities-in", help="Facilities in a city")
    parser.add_argument("--search", help="Search networks by name")
    parser.add_argument("--raw-json", action="store_true", help="Raw JSON output")

    args = parser.parse_args()
    client = PeeringDB()

    if args.asn:
        info = client.get_full_network_info(args.asn)
        if not info:
            print("No network found for AS{}".format(args.asn))
            sys.exit(1)
        if args.raw_json:
            print(json.dumps(info, indent=2))
        else:
            net = info["network"]
            print("=== Network: AS{} ===".format(args.asn))
            print("  Name:          {}".format(net.get("name", "")))
            print("  Website:       {}".format(net.get("website", "")))
            print("  IRR AS-SET:    {}".format(net.get("irr_as_set", "")))
            print("  Info Type:     {}".format(net.get("info_type", "")))
            print("  Info Ratio:    {}".format(net.get("info_ratio", "")))
            print("  Info Traffic:  {}".format(net.get("info_traffic", "")))
            print("  Info Prefixes4:{}".format(net.get("info_prefixes4", "")))
            print("  Info Prefixes6:{}".format(net.get("info_prefixes6", "")))
            print("  Policy:        {}".format(net.get("policy_general", "")))
            print("  Policy URL:    {}".format(net.get("policy_url", "")))
            print("  Looking Glass: {}".format(net.get("looking_glass", "")))
            print("  Route Server:  {}".format(net.get("route_server", "")))
            print("  Notes:         {}".format(net.get("notes", "")[:200]))
            print()

            ixlans = info["ix_presence"]
            print("=== IX Presence ({} sessions) ===".format(len(ixlans)))
            # Group by IX
            ix_groups = {}
            for entry in ixlans:
                name = entry.get("name", "?")
                if name not in ix_groups:
                    ix_groups[name] = []
                ix_groups[name].append(entry)
            for ix_name, sessions in sorted(ix_groups.items()):
                total_speed = sum(s.get("speed", 0) for s in sessions)
                print("  {} ({} sessions, {})".format(ix_name, len(sessions), format_speed(total_speed)))
                for s in sessions:
                    rs = " [RS]" if s.get("is_rs_peer") else ""
                    print("    v4={} v6={} speed={}{}".format(
                        s.get("ipaddr4", "-"), s.get("ipaddr6", "-"),
                        format_speed(s.get("speed", 0)), rs))
            print()

            facs = info["facilities"]
            print("=== Facility Presence ({} facilities) ===".format(len(facs)))
            for f in sorted(facs, key=lambda x: x.get("name", "")):
                print("  {} ({}, {})".format(f.get("name", ""), f.get("city", ""), f.get("country", "")))
            print()

            contacts = info["contacts"]
            print("=== Contacts ({}) ===".format(len(contacts)))
            for c in contacts:
                print("  {} ({}): {} / {}".format(c.get("name", ""), c.get("role", ""),
                      c.get("email", ""), c.get("phone", "")))

    elif args.exchanges_for_asn:
        exchanges = client.get_exchanges_for_asn(args.exchanges_for_asn)
        if args.raw_json:
            print(json.dumps(exchanges, indent=2))
        else:
            print("=== IXs for AS{} ({} exchanges) ===".format(args.exchanges_for_asn, len(exchanges)))
            for ix in sorted(exchanges, key=lambda x: x["ix_name"]):
                total_speed = sum(s.get("speed", 0) for s in ix["sessions"])
                rs_count = sum(1 for s in ix["sessions"] if s.get("is_rs_peer"))
                print("  {} (id={}, {} sessions, {}, {} RS)".format(
                    ix["ix_name"], ix["ix_id"], len(ix["sessions"]),
                    format_speed(total_speed), rs_count))

    elif args.peers_at_ix:
        peers = client.get_peers_at_ix(args.peers_at_ix)
        if args.raw_json:
            print(json.dumps(peers, indent=2))
        else:
            print("=== Peers at IX {} ({} entries) ===".format(args.peers_at_ix, len(peers)))
            print("{:<8} {:<35} {:<18} {:<8}".format("ASN", "Name", "IPv4", "Speed"))
            print("-" * 75)
            for p in sorted(peers, key=lambda x: x.get("asn", 0)):
                print("{:<8} {:<35} {:<18} {}".format(
                    "AS{}".format(p.get("asn", "")),
                    p.get("name", "")[:34],
                    p.get("ipaddr4", "-"),
                    format_speed(p.get("speed", 0))))

    elif args.ix_search:
        results = client.ix_search(args.ix_search)
        if args.raw_json:
            print(json.dumps(results, indent=2))
        else:
            print("=== IX Search: '{}' ({} results) ===".format(args.ix_search, len(results)))
            for ix in results:
                print("  [{}] {} ({}, {})".format(ix.get("id", ""), ix.get("name", ""),
                      ix.get("city", ""), ix.get("country", "")))

    elif args.facility_search:
        results = client.facility_search(args.facility_search)
        if args.raw_json:
            print(json.dumps(results, indent=2))
        else:
            print("=== Facility Search: '{}' ({} results) ===".format(args.facility_search, len(results)))
            for f in results:
                print("  [{}] {} ({}, {})".format(f.get("id", ""), f.get("name", ""),
                      f.get("city", ""), f.get("country", "")))

    elif args.facilities_in:
        results = client.facilities_in_city(args.facilities_in)
        if args.raw_json:
            print(json.dumps(results, indent=2))
        else:
            print("=== Facilities in '{}' ({} results) ===".format(args.facilities_in, len(results)))
            for f in results:
                print("  [{}] {} - {}".format(f.get("id", ""), f.get("name", ""), f.get("address1", "")))

    elif args.search:
        results = client.network_search(args.search)
        if args.raw_json:
            print(json.dumps(results, indent=2))
        else:
            print("=== Network Search: '{}' ({} results) ===".format(args.search, len(results)))
            for n in results:
                print("  AS{:<8} {} ({})".format(n.get("asn", ""), n.get("name", ""), n.get("info_type", "")))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
