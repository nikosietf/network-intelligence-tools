#!/usr/bin/env python3
"""
IX Carrier Peering Gap Analysis — Find carriers at shared IXs not yet peered.

Uses PeeringDB to identify carrier/NSP networks present at the same IXs as a
target ASN, helping discover peering opportunities.

Limitation: PeeringDB shows IX co-location, not actual BGP sessions.
"Not peered" here means "present at same IX but no bilateral session
visible in PeeringDB." Route-server peering is flagged separately.

Usage:
    python3 ix_peering_gaps.py --asn 13335
    python3 ix_peering_gaps.py --asn 13335 --type NSP
    python3 ix_peering_gaps.py --asn 13335 --min-speed 10000
    python3 ix_peering_gaps.py --asn 13335 --raw-json

Author: Nikos Leontsinis
License: MIT
"""
from __future__ import annotations

import argparse
import json
import sys
import time

import requests

BASE_URL = "https://www.peeringdb.com/api"

# PeeringDB info_type values for carrier/transit networks
CARRIER_TYPES = {"NSP", "Cable/DSL/ISP"}


class PeeringDBError(Exception):
    pass


class PeeringDBClient:
    """Minimal PeeringDB client for peering gap analysis."""

    def __init__(self, timeout: int = 60):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json"})

    def _get(self, endpoint: str, params: dict | None = None) -> list:
        url = f"{BASE_URL}/{endpoint}"
        for attempt in range(5):
            resp = self.session.get(url, params=params, timeout=self.timeout)
            if resp.status_code == 429:
                wait = 3 * (attempt + 1)
                print(f"     Rate limited, waiting {wait}s...", file=sys.stderr)
                time.sleep(wait)
                continue
            resp.raise_for_status()
            return resp.json().get("data", [])
        resp.raise_for_status()
        return []

    def network_by_asn(self, asn: int) -> dict | None:
        results = self._get("net", {"asn": asn})
        return results[0] if results else None

    def netixlan_by_net(self, net_id: int) -> list:
        """All IX LAN entries for a network."""
        return self._get("netixlan", {"net_id": net_id})

    def netixlan_by_ix_ids(self, ix_ids: list[int]) -> list:
        """All participants at multiple IXs (bulk query)."""
        ids_str = ",".join(str(x) for x in ix_ids)
        return self._get("netixlan", {"ix_id__in": ids_str})

    def networks_by_type(self, info_type: str) -> list:
        """Get all networks of a given type (NSP, Cable/DSL/ISP, etc.)."""
        return self._get("net", {"info_type": info_type})


def format_speed(speed_mbps: int) -> str:
    if speed_mbps >= 1000000:
        return f"{speed_mbps // 1000000}T"
    elif speed_mbps >= 1000:
        return f"{speed_mbps // 1000}G"
    return f"{speed_mbps}M"


def analyze_peering_gaps(
    asn: int,
    network_types: set[str] | None = None,
    min_speed_mbps: int = 0,
) -> dict:
    """
    Find carriers at shared IXs that the target ASN doesn't peer with.

    Strategy: Only 4-5 total API calls using bulk queries:
      1. net?asn=X          → get our net_id
      2. netixlan?net_id=X  → get our IX list
      3. netixlan?ix_id__in=... → all participants at our IXs (one call!)
      4. net?info_type=NSP  → all NSP networks (for filtering)
      5. net?info_type=Cable/DSL/ISP → all Cable networks (optional)
    """
    if network_types is None:
        network_types = CARRIER_TYPES

    client = PeeringDBClient()

    # Step 1: Get target network
    print(f"[1/5] Looking up AS{asn}...", file=sys.stderr)
    target_net = client.network_by_asn(asn)
    if not target_net:
        raise PeeringDBError(f"No network found for AS{asn}")
    net_id = target_net["id"]
    target_name = target_net.get("name", f"AS{asn}")

    # Step 2: Get target's IX presence
    time.sleep(2)
    print(f"[2/5] Fetching IX presence for {target_name}...", file=sys.stderr)
    my_ixlans = client.netixlan_by_net(net_id)

    my_ix_ids = {}
    for entry in my_ixlans:
        ix_id = entry.get("ix_id")
        ix_name = entry.get("name", f"IX-{ix_id}")
        if ix_id not in my_ix_ids:
            my_ix_ids[ix_id] = {"name": ix_name, "my_speed": 0, "my_rs_peer": False}
        my_ix_ids[ix_id]["my_speed"] += entry.get("speed", 0)
        if entry.get("is_rs_peer"):
            my_ix_ids[ix_id]["my_rs_peer"] = True

    print(f"     Found {len(my_ix_ids)} IXs", file=sys.stderr)

    # Step 3: Bulk fetch all participants at our IXs
    time.sleep(2)
    print(f"[3/5] Fetching all participants at {len(my_ix_ids)} IXs (bulk)...", file=sys.stderr)
    all_entries = client.netixlan_by_ix_ids(list(my_ix_ids.keys()))
    print(f"     {len(all_entries)} total participant entries", file=sys.stderr)

    # Step 4: Fetch carrier/NSP network list (server-side filtered)
    print(f"[4/5] Fetching carrier network database...", file=sys.stderr)
    carrier_nets = {}  # net_id -> network info
    for ntype in network_types:
        time.sleep(2)
        nets = client.networks_by_type(ntype)
        print(f"     {len(nets)} {ntype} networks", file=sys.stderr)
        for n in nets:
            carrier_nets[n["id"]] = n

    print(f"     {len(carrier_nets)} total carrier networks loaded", file=sys.stderr)

    # Step 5: Cross-reference — find carriers at our IXs
    print(f"[5/5] Analyzing peering gaps...", file=sys.stderr)

    carrier_ix_map = {}

    for entry in all_entries:
        entry_asn = entry.get("asn")
        if entry_asn == asn:
            continue  # skip ourselves

        entry_net_id = entry.get("net_id")
        if entry_net_id not in carrier_nets:
            continue  # not a carrier

        entry_speed = entry.get("speed", 0)
        if entry_speed < min_speed_mbps:
            continue

        ix_id = entry.get("ix_id")
        net_info = carrier_nets[entry_net_id]

        if entry_asn not in carrier_ix_map:
            carrier_ix_map[entry_asn] = {
                "asn": entry_asn,
                "name": net_info.get("name", f"AS{entry_asn}"),
                "info_type": net_info.get("info_type", ""),
                "policy": net_info.get("policy_general", ""),
                "info_traffic": net_info.get("info_traffic", ""),
                "shared_ixs": [],
            }

        carrier_ix_map[entry_asn]["shared_ixs"].append({
            "ix_id": ix_id,
            "ix_name": my_ix_ids.get(ix_id, {}).get("name", f"IX-{ix_id}"),
            "their_speed": entry_speed,
            "their_rs_peer": entry.get("is_rs_peer", False),
            "their_ipv4": entry.get("ipaddr4", ""),
            "their_ipv6": entry.get("ipaddr6", ""),
        })

    carriers = sorted(carrier_ix_map.values(), key=lambda c: len(c["shared_ixs"]), reverse=True)

    return {
        "target_asn": asn,
        "target_name": target_name,
        "target_ix_count": len(my_ix_ids),
        "total_carriers_at_shared_ixs": len(carriers),
        "carriers": carriers,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Find carriers at shared IXs for peering opportunities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --asn 13335                     All carriers at AS13335's IXs
  %(prog)s --asn 13335 --type NSP          Only NSP-type networks
  %(prog)s --asn 13335 --min-speed 10000   Only carriers with >=10G ports
  %(prog)s --asn 13335 --top 20            Show top 20 by shared IX count
  %(prog)s --asn 13335 --raw-json          Full JSON output
""")

    query = parser.add_argument_group("query")
    query.add_argument("--asn", type=int, required=True, help="Target ASN")
    query.add_argument("--type", nargs="+", default=None,
                       help="Network types to include (default: NSP, Cable/DSL/ISP)")
    query.add_argument("--min-speed", type=int, default=0,
                       help="Minimum port speed in Mbps (e.g. 10000 for 10G)")

    output = parser.add_argument_group("output")
    output.add_argument("--top", type=int, default=0, help="Show only top N results")
    output.add_argument("--raw-json", action="store_true", help="JSON output")

    args = parser.parse_args()

    network_types = set(args.type) if args.type else CARRIER_TYPES

    try:
        report = analyze_peering_gaps(args.asn, network_types, args.min_speed)
    except PeeringDBError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except requests.RequestException as e:
        print(f"API error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.raw_json:
        print(json.dumps(report, indent=2))
        return

    # Pretty print
    print(f"\n=== Carrier Peering Gaps for AS{report['target_asn']} ({report['target_name']}) ===")
    print(f"    Present at {report['target_ix_count']} IXs")
    print(f"    {report['total_carriers_at_shared_ixs']} carriers found at shared IXs\n")

    carriers = report["carriers"]
    if args.top:
        carriers = carriers[:args.top]

    print(f"{'ASN':<10} {'Name':<40} {'Policy':<12} {'Shared IXs':<10} {'Top IXs'}")
    print("-" * 110)

    for c in carriers:
        shared = c["shared_ixs"]
        top_ixs = ", ".join(s["ix_name"].split(":")[0][:20] for s in shared[:3])
        if len(shared) > 3:
            top_ixs += f" (+{len(shared)-3} more)"
        print(f"AS{c['asn']:<8} {c['name'][:39]:<40} {c['policy']:<12} {len(shared):<10} {top_ixs}")

    print(f"\n--- Total: {len(carriers)} carriers shown ---")
    if args.top and args.top < report["total_carriers_at_shared_ixs"]:
        print(f"    (Use --top 0 or omit to see all {report['total_carriers_at_shared_ixs']})")


if __name__ == "__main__":
    main()
