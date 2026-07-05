#!/usr/bin/env python3
"""
BGP Hidden Prefixes Report for Juniper Routers

Connects to Juniper routers via NETCONF/PyEZ, retrieves BGP neighbor information,
and reports all hidden prefixes with the reason they are being rejected.

Usage:
    python3 bgp_hidden_prefixes_report.py --hosts router1,router2,router3
    python3 bgp_hidden_prefixes_report.py --hosts-file routers.txt
    python3 bgp_hidden_prefixes_report.py --hosts router1 --username admin

Environment Variables:
    JUNOS_USERNAME - SSH username (default: current user)
    JUNOS_PASSWORD - SSH password (optional if using SSH keys)
    JUNOS_SSH_KEY  - Path to SSH private key (optional)

Output:
    - Console summary
    - JSON report: bgp_hidden_prefixes_report_<timestamp>.json
    - CSV report: bgp_hidden_prefixes_report_<timestamp>.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any

try:
    from jnpr.junos import Device
    from jnpr.junos.exception import ConnectError, RpcError, ConnectAuthError
    from lxml import etree
except ImportError:
    print("ERROR: Required packages not installed. Run:")
    print("  pip install junos-eznc lxml")
    sys.exit(1)


@dataclass
class HiddenPrefix:
    """Represents a single hidden prefix from a BGP neighbor."""
    prefix: str
    prefix_length: int
    protocol_next_hop: str
    local_preference: int | None
    as_path: str
    origin: str
    communities: list[str]
    hidden_reason: str
    validation_state: str | None = None
    med: int | None = None


@dataclass
class BGPNeighbor:
    """Represents a BGP neighbor with its hidden prefixes."""
    peer_address: str
    peer_as: int
    peer_state: str
    description: str
    local_address: str
    hidden_prefix_count: int = 0
    hidden_prefixes: list[HiddenPrefix] = field(default_factory=list)


@dataclass
class RouterReport:
    """Report for a single router."""
    hostname: str
    timestamp: str
    success: bool
    error_message: str | None = None
    total_bgp_peers: int = 0
    peers_with_hidden: int = 0
    total_hidden_prefixes: int = 0
    neighbors: list[BGPNeighbor] = field(default_factory=list)


def parse_bgp_summary(xml_response: etree._Element) -> list[dict[str, Any]]:
    """Parse BGP summary XML to extract peer information."""
    peers = []

    # Handle both formats: bgp-information and bgp-peer-information
    for peer in xml_response.findall(".//bgp-peer"):
        peer_info = {
            "peer_address": peer.findtext("peer-address", "").strip(),
            "peer_as": int(peer.findtext("peer-as", "0") or "0"),
            "peer_state": peer.findtext("peer-state", "").strip(),
            "description": peer.findtext("description", "").strip(),
            "local_address": peer.findtext("local-address", "").strip().split("+")[0],
        }
        if peer_info["peer_address"]:
            peers.append(peer_info)

    return peers


def extract_hidden_reason(route_elem: etree._Element) -> str:
    """Extract the reason why a prefix is hidden."""
    reasons = []

    # Check various hidden reason indicators
    inactive_reason = route_elem.findtext(".//inactive-reason")
    if inactive_reason:
        reasons.append(inactive_reason.strip())

    # Check for validation state (RPKI)
    validation = route_elem.findtext(".//validation-state")
    if validation and validation.lower() in ("invalid", "unknown"):
        reasons.append(f"RPKI: {validation}")

    # Check for specific rejection reasons in communities or attributes
    for rt_entry in route_elem.findall(".//rt-entry"):
        # Check protocol attributes
        for attr in rt_entry.findall(".//protocol-attribute"):
            attr_name = attr.findtext("attribute-name", "")
            if "reject" in attr_name.lower() or "hidden" in attr_name.lower():
                reasons.append(attr_name)

        # Check for inactive reasons at entry level
        entry_inactive = rt_entry.findtext("inactive-reason")
        if entry_inactive and entry_inactive not in reasons:
            reasons.append(entry_inactive.strip())

        # Check for reject communities
        for comm in rt_entry.findall(".//community"):
            comm_text = comm.text or ""
            if "reject" in comm_text.lower() or "no-export" in comm_text.lower():
                reasons.append(f"Community: {comm_text}")

    # Check for hidden attribute directly
    hidden_elem = route_elem.find(".//hidden")
    if hidden_elem is not None:
        hidden_text = hidden_elem.text or "true"
        if hidden_text.lower() == "true" and not reasons:
            reasons.append("Marked as hidden")

    # Check for policy rejection
    for announce in route_elem.findall(".//announce-*"):
        if "reject" in (announce.text or "").lower():
            reasons.append(f"Policy: {announce.text}")

    # Check tiebreaker info for why route lost
    for tiebreaker in route_elem.findall(".//tiebreaker"):
        tb_name = tiebreaker.findtext("tiebreaker-name", "")
        if tb_name:
            reasons.append(f"Tiebreaker: {tb_name}")

    # If still no reason, check if it's simply not-best
    if not reasons:
        active_tag = route_elem.find(".//active-tag")
        if active_tag is None:
            # Check for specific inactive indicators
            for rt_entry in route_elem.findall(".//rt-entry"):
                if rt_entry.find(".//inactive-reason") is None:
                    # Look for any hint
                    preference = rt_entry.findtext(".//preference")
                    local_pref = rt_entry.findtext(".//local-preference")
                    if preference or local_pref:
                        reasons.append("Not best path (preference/policy)")

    return "; ".join(reasons) if reasons else "Unknown (hidden by policy or not-best)"


def parse_hidden_routes(xml_response: etree._Element) -> list[HiddenPrefix]:
    """Parse hidden routes XML to extract prefix details."""
    hidden_prefixes = []

    for rt in xml_response.findall(".//rt"):
        # Get destination prefix
        rt_dest = rt.findtext("rt-destination", "")
        if not rt_dest:
            continue

        # Parse prefix and length
        if "/" in rt_dest:
            prefix, prefix_len = rt_dest.split("/", 1)
            prefix_length = int(prefix_len)
        else:
            prefix = rt_dest
            prefix_length = 32  # Assume /32 for host routes

        for rt_entry in rt.findall(".//rt-entry"):
            # Extract route attributes
            protocol_nh = rt_entry.findtext(".//protocol-nh/to", "")
            if not protocol_nh:
                protocol_nh = rt_entry.findtext(".//nh/to", "")

            local_pref_text = rt_entry.findtext(".//local-preference")
            local_pref = int(local_pref_text) if local_pref_text else None

            med_text = rt_entry.findtext(".//med") or rt_entry.findtext(".//metric")
            med = int(med_text) if med_text else None

            # AS Path
            as_path_elem = rt_entry.find(".//as-path")
            as_path = as_path_elem.text.strip() if as_path_elem is not None and as_path_elem.text else ""

            # Origin
            origin = rt_entry.findtext(".//origin", "")

            # Communities
            communities = []
            for comm in rt_entry.findall(".//community"):
                if comm.text:
                    communities.append(comm.text.strip())

            # Validation state (RPKI)
            validation_state = rt_entry.findtext(".//validation-state")

            # Hidden reason
            hidden_reason = extract_hidden_reason(rt)

            hidden_prefix = HiddenPrefix(
                prefix=prefix,
                prefix_length=prefix_length,
                protocol_next_hop=protocol_nh,
                local_preference=local_pref,
                as_path=as_path,
                origin=origin,
                communities=communities,
                hidden_reason=hidden_reason,
                validation_state=validation_state,
                med=med,
            )
            hidden_prefixes.append(hidden_prefix)

    return hidden_prefixes


def collect_bgp_data(
    hostname: str,
    username: str,
    password: str | None = None,
    ssh_key: str | None = None,
    port: int = 830,
    timeout: int = 60,
) -> RouterReport:
    """Collect BGP hidden prefix data from a single router."""

    timestamp = datetime.utcnow().isoformat() + "Z"
    report = RouterReport(
        hostname=hostname,
        timestamp=timestamp,
        success=False,
    )

    # Connection parameters
    conn_params: dict[str, Any] = {
        "host": hostname,
        "user": username,
        "port": port,
        "timeout": timeout,
        "normalize": True,
    }

    if password:
        conn_params["password"] = password
    if ssh_key:
        conn_params["ssh_private_key_file"] = ssh_key

    try:
        print(f"[{hostname}] Connecting via NETCONF...")
        dev = Device(**conn_params)
        dev.open()

        try:
            # Get BGP summary
            print(f"[{hostname}] Retrieving BGP summary...")
            bgp_summary = dev.rpc.get_bgp_summary_information()
            peers = parse_bgp_summary(bgp_summary)

            report.total_bgp_peers = len(peers)
            print(f"[{hostname}] Found {len(peers)} BGP peers")

            # For each peer, get hidden routes
            for peer_info in peers:
                peer_addr = peer_info["peer_address"]

                # Skip peers that are not established
                if peer_info["peer_state"].lower() != "established":
                    print(f"[{hostname}] Skipping peer {peer_addr} (state: {peer_info['peer_state']})")
                    continue

                print(f"[{hostname}] Checking hidden prefixes from {peer_addr}...")

                try:
                    # Get hidden routes with extensive output
                    # RPC: show route receive-protocol bgp <peer> hidden extensive
                    hidden_routes = dev.rpc.get_route_information(
                        protocol="bgp",
                        peer=peer_addr,
                        hidden=True,
                        extensive=True,
                    )

                    hidden_prefixes = parse_hidden_routes(hidden_routes)

                    neighbor = BGPNeighbor(
                        peer_address=peer_addr,
                        peer_as=peer_info["peer_as"],
                        peer_state=peer_info["peer_state"],
                        description=peer_info["description"],
                        local_address=peer_info["local_address"],
                        hidden_prefix_count=len(hidden_prefixes),
                        hidden_prefixes=hidden_prefixes,
                    )

                    if hidden_prefixes:
                        report.peers_with_hidden += 1
                        report.total_hidden_prefixes += len(hidden_prefixes)
                        print(f"[{hostname}]   -> {len(hidden_prefixes)} hidden prefixes from {peer_addr}")

                    report.neighbors.append(neighbor)

                except RpcError as e:
                    print(f"[{hostname}] Warning: RPC error for peer {peer_addr}: {e}")
                    # Still add the neighbor but with no hidden prefixes
                    neighbor = BGPNeighbor(
                        peer_address=peer_addr,
                        peer_as=peer_info["peer_as"],
                        peer_state=peer_info["peer_state"],
                        description=peer_info["description"],
                        local_address=peer_info["local_address"],
                    )
                    report.neighbors.append(neighbor)

            report.success = True
            print(f"[{hostname}] Complete: {report.total_hidden_prefixes} hidden prefixes from {report.peers_with_hidden} peers")

        finally:
            dev.close()

    except ConnectAuthError as e:
        report.error_message = f"Authentication failed: {e}"
        print(f"[{hostname}] ERROR: {report.error_message}")
    except ConnectError as e:
        report.error_message = f"Connection failed: {e}"
        print(f"[{hostname}] ERROR: {report.error_message}")
    except Exception as e:
        report.error_message = f"Unexpected error: {e}"
        print(f"[{hostname}] ERROR: {report.error_message}")

    return report


def generate_csv_report(reports: list[RouterReport], output_file: str) -> None:
    """Generate CSV report of hidden prefixes."""

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        # Header
        writer.writerow([
            "Router",
            "Timestamp",
            "Neighbor",
            "Neighbor_AS",
            "Neighbor_Description",
            "Prefix",
            "Prefix_Length",
            "Next_Hop",
            "Local_Preference",
            "MED",
            "AS_Path",
            "Origin",
            "Communities",
            "Validation_State",
            "Hidden_Reason",
        ])

        for report in reports:
            if not report.success:
                continue

            for neighbor in report.neighbors:
                for prefix in neighbor.hidden_prefixes:
                    writer.writerow([
                        report.hostname,
                        report.timestamp,
                        neighbor.peer_address,
                        neighbor.peer_as,
                        neighbor.description,
                        prefix.prefix,
                        prefix.prefix_length,
                        prefix.protocol_next_hop,
                        prefix.local_preference or "",
                        prefix.med or "",
                        prefix.as_path,
                        prefix.origin,
                        "|".join(prefix.communities),
                        prefix.validation_state or "",
                        prefix.hidden_reason,
                    ])

    print(f"\nCSV report written to: {output_file}")


def generate_json_report(reports: list[RouterReport], output_file: str) -> None:
    """Generate JSON report of hidden prefixes."""

    # Convert dataclasses to dicts
    report_data = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "total_routers": len(reports),
            "successful_routers": sum(1 for r in reports if r.success),
            "failed_routers": sum(1 for r in reports if not r.success),
            "total_hidden_prefixes": sum(r.total_hidden_prefixes for r in reports),
            "total_peers_with_hidden": sum(r.peers_with_hidden for r in reports),
        },
        "routers": [],
    }

    for report in reports:
        router_dict = asdict(report)
        report_data["routers"].append(router_dict)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, default=str)

    print(f"JSON report written to: {output_file}")


def print_summary(reports: list[RouterReport]) -> None:
    """Print summary to console."""

    print("\n" + "=" * 80)
    print("BGP HIDDEN PREFIXES REPORT SUMMARY")
    print("=" * 80)

    total_hidden = 0
    total_peers = 0

    for report in reports:
        status = "OK" if report.success else f"FAILED: {report.error_message}"
        print(f"\n{report.hostname}: {status}")

        if report.success:
            print(f"  BGP Peers: {report.total_bgp_peers}")
            print(f"  Peers with hidden prefixes: {report.peers_with_hidden}")
            print(f"  Total hidden prefixes: {report.total_hidden_prefixes}")

            total_hidden += report.total_hidden_prefixes
            total_peers += report.peers_with_hidden

            # Show top reasons
            reason_counts: dict[str, int] = {}
            for neighbor in report.neighbors:
                for prefix in neighbor.hidden_prefixes:
                    reason = prefix.hidden_reason
                    reason_counts[reason] = reason_counts.get(reason, 0) + 1

            if reason_counts:
                print("  Top hidden reasons:")
                for reason, count in sorted(reason_counts.items(), key=lambda x: -x[1])[:5]:
                    print(f"    - {reason}: {count}")

    print("\n" + "-" * 80)
    print(f"TOTAL: {total_hidden} hidden prefixes from {total_peers} peers across {len(reports)} routers")
    print("=" * 80)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect BGP hidden prefixes from Juniper routers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Host specification
    host_group = parser.add_mutually_exclusive_group(required=True)
    host_group.add_argument(
        "--hosts",
        help="Comma-separated list of router hostnames/IPs",
    )
    host_group.add_argument(
        "--hosts-file",
        help="File containing router hostnames (one per line)",
    )

    # Authentication
    parser.add_argument(
        "--username",
        default=os.environ.get("DEVICE_USERNAME", os.environ.get("JUNOS_USERNAME", os.environ.get("USER", "admin"))),
        help="SSH username (default: $DEVICE_USERNAME or $JUNOS_USERNAME or current user)",
    )
    parser.add_argument(
        "--password",
        default=os.environ.get("DEVICE_PASSWORD", os.environ.get("JUNOS_PASSWORD")),
        help="SSH password (default: $DEVICE_PASSWORD or $JUNOS_PASSWORD or use SSH keys)",
    )
    parser.add_argument(
        "--ssh-key",
        default=os.environ.get("JUNOS_SSH_KEY"),
        help="Path to SSH private key (default: $JUNOS_SSH_KEY)",
    )

    # Connection options
    parser.add_argument(
        "--port",
        type=int,
        default=22,
        help="NETCONF port (default: 22)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Connection timeout in seconds (default: 60)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=5,
        help="Number of parallel workers (default: 5)",
    )

    # Output options
    parser.add_argument(
        "--output-prefix",
        default="bgp_hidden_prefixes_report",
        help="Output file prefix (default: bgp_hidden_prefixes_report)",
    )
    parser.add_argument(
        "--no-csv",
        action="store_true",
        help="Skip CSV output",
    )
    parser.add_argument(
        "--no-json",
        action="store_true",
        help="Skip JSON output",
    )

    args = parser.parse_args()

    # Get host list
    if args.hosts:
        hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
    else:
        with open(args.hosts_file, "r") as f:
            hosts = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    if not hosts:
        print("ERROR: No hosts specified")
        sys.exit(1)

    print(f"Collecting BGP hidden prefix data from {len(hosts)} router(s)...")
    print(f"Username: {args.username}")
    print(f"Using SSH key: {args.ssh_key or 'No (password or default key)'}")
    print()

    # Collect data from all routers
    reports: list[RouterReport] = []

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(
                collect_bgp_data,
                hostname=host,
                username=args.username,
                password=args.password,
                ssh_key=args.ssh_key,
                port=args.port,
                timeout=args.timeout,
            ): host
            for host in hosts
        }

        for future in as_completed(futures):
            host = futures[future]
            try:
                report = future.result()
                reports.append(report)
            except Exception as e:
                print(f"[{host}] Unexpected error: {e}")
                reports.append(RouterReport(
                    hostname=host,
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    success=False,
                    error_message=str(e),
                ))

    # Sort reports by hostname
    reports.sort(key=lambda r: r.hostname)

    # Generate timestamp for output files
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Generate reports
    if not args.no_json:
        json_file = f"{args.output_prefix}_{ts}.json"
        generate_json_report(reports, json_file)

    if not args.no_csv:
        csv_file = f"{args.output_prefix}_{ts}.csv"
        generate_csv_report(reports, csv_file)

    # Print summary
    print_summary(reports)


if __name__ == "__main__":
    main()
