#!/usr/bin/env python3
"""
RIPEstat Data API Client — Query all available endpoints.

A comprehensive Python client for the RIPEstat Data API, providing access to
BGP routing data, WHOIS information, geolocation, RPKI validation, and more.

Usage:
    from ripestat_client import RIPEstat

    client = RIPEstat(sourceapp="my-network-tool")
    result = client.prefix_overview(resource="193.0.0.0/21")
    result = client.bgp_state(resource="AS3333")
    result = client.abuse_contact_finder(resource="8.8.8.8")

All methods return the parsed JSON response dict.
Rate-limited to 8 concurrent requests per the API rules.

Author: Nikos Leontsinis
License: MIT
"""

import time
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Optional
from urllib.parse import urlencode

import requests

logger = logging.getLogger(__name__)

BASE_URL = "https://stat.ripe.net/data"


class RIPEstatError(Exception):
    """Raised when an API call returns an error status."""
    pass


class RIPEstat:
    """Client for the RIPEstat Data API (read-only)."""

    # All known endpoints mapped to their URL slug
    ENDPOINTS = [
        "abuse-contact-finder",
        "address-space-hierarchy",
        "address-space-usage",
        "allocation-history",
        "announced-prefixes",
        "as-overview",
        "as-path-length",
        "as-routing-consistency",
        "asn-neighbours",
        "asn-neighbours-history",
        "atlas-probe-deployment",
        "atlas-probes",
        "atlas-targets",
        "bgp-state",
        "bgp-update-activity",
        "bgp-updates",
        "bgplay",
        "country-asns",
        "country-resource-list",
        "country-resource-stats",
        "dns-blocklists",
        "dns-chain",
        "example-resources",
        "historical-whois",
        "iana-registry-info",
        "looking-glass",
        "maxmind-geo-lite",
        "maxmind-geo-lite-announced-by-as",
        "network-info",
        "prefix-count",
        "prefix-overview",
        "prefix-routing-consistency",
        "prefix-size-distribution",
        "related-prefixes",
        "reverse-dns",
        "reverse-dns-consistency",
        "reverse-dns-ip",
        "rir",
        "rir-geo",
        "rir-prefix-size-distribution",
        "rir-stats-country",
        "ris-asns",
        "ris-first-last-seen",
        "ris-full-table-threshold",
        "ris-peer-count",
        "ris-peerings",
        "ris-peers",
        "ris-prefixes",
        "routing-history",
        "routing-status",
        "rpki-history",
        "rpki-validation",
        "rrc-info",
        "searchcomplete",
        "transfer-history",
        "visibility",
        "whats-my-ip",
        "whois",
        "whois-object-last-updated",
        "zonemaster",
    ]

    def __init__(
        self,
        sourceapp="ripestat-python-client",
        timeout=30,
        max_concurrent=8,
    ):
        self.sourceapp = sourceapp
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json"})

    def _request(self, endpoint, params=None):
        """Execute a single API request."""
        params = params or {}
        params["sourceapp"] = self.sourceapp
        # Remove None values
        params = {k: v for k, v in params.items() if v is not None}

        url = f"{BASE_URL}/{endpoint}/data.json"
        logger.debug("GET %s?%s", url, urlencode(params))

        resp = self.session.get(url, params=params, timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()

        if data.get("status") == "error":
            msg = data.get("message", "Unknown API error")
            raise RIPEstatError(f"{endpoint}: {msg}")

        return data

    def _get_meta(self, endpoint, meta_type="methodology"):
        """Get metadata for an endpoint (methodology, versions, availability)."""
        url = f"{BASE_URL}/{endpoint}/meta/{meta_type}"
        resp = self.session.get(url, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    # --- Individual endpoint methods ---

    def abuse_contact_finder(self, resource, **kwargs):
        """Return abuse contact information for an Internet number resource."""
        return self._request("abuse-contact-finder", {"resource": resource, **kwargs})

    def address_space_hierarchy(self, resource, **kwargs):
        """Show address space hierarchy for a prefix."""
        return self._request("address-space-hierarchy", {"resource": resource, **kwargs})

    def address_space_usage(self, resource, **kwargs):
        """Show address space usage for a prefix."""
        return self._request("address-space-usage", {"resource": resource, **kwargs})

    def allocation_history(self, resource, **kwargs):
        """Show allocation history for a resource."""
        return self._request("allocation-history", {"resource": resource, **kwargs})

    def announced_prefixes(self, resource, **kwargs):
        """List all prefixes announced by an ASN."""
        return self._request("announced-prefixes", {"resource": resource, **kwargs})

    def as_overview(self, resource, **kwargs):
        """General information about an ASN."""
        return self._request("as-overview", {"resource": resource, **kwargs})

    def as_path_length(self, resource, **kwargs):
        """AS path length statistics."""
        return self._request("as-path-length", {"resource": resource, **kwargs})

    def as_routing_consistency(self, resource, **kwargs):
        """Routing consistency for an ASN."""
        return self._request("as-routing-consistency", {"resource": resource, **kwargs})

    def asn_neighbours(self, resource, **kwargs):
        """List BGP neighbours of an ASN."""
        return self._request("asn-neighbours", {"resource": resource, **kwargs})

    def asn_neighbours_history(self, resource, **kwargs):
        """Historical BGP neighbours of an ASN."""
        return self._request("asn-neighbours-history", {"resource": resource, **kwargs})

    def atlas_probe_deployment(self, resource, **kwargs):
        """RIPE Atlas probe deployment info."""
        return self._request("atlas-probe-deployment", {"resource": resource, **kwargs})

    def atlas_probes(self, resource, **kwargs):
        """RIPE Atlas probes for a resource."""
        return self._request("atlas-probes", {"resource": resource, **kwargs})

    def atlas_targets(self, resource, **kwargs):
        """RIPE Atlas measurement targets."""
        return self._request("atlas-targets", {"resource": resource, **kwargs})

    def bgp_state(self, resource, **kwargs):
        """Current BGP state for a resource."""
        return self._request("bgp-state", {"resource": resource, **kwargs})

    def bgp_update_activity(self, resource, **kwargs):
        """BGP update activity for a resource."""
        return self._request("bgp-update-activity", {"resource": resource, **kwargs})

    def bgp_updates(self, resource, **kwargs):
        """BGP updates for a resource."""
        return self._request("bgp-updates", {"resource": resource, **kwargs})

    def bgplay(self, resource, **kwargs):
        """BGPlay data for visualising BGP routing."""
        return self._request("bgplay", {"resource": resource, **kwargs})

    def country_asns(self, resource, **kwargs):
        """ASNs registered in a country (2-letter ISO code)."""
        return self._request("country-asns", {"resource": resource, **kwargs})

    def country_resource_list(self, resource, **kwargs):
        """Internet number resources for a country."""
        return self._request("country-resource-list", {"resource": resource, **kwargs})

    def country_resource_stats(self, resource, **kwargs):
        """Resource statistics for a country."""
        return self._request("country-resource-stats", {"resource": resource, **kwargs})

    def dns_blocklists(self, resource, **kwargs):
        """DNS blocklist status for a resource."""
        return self._request("dns-blocklists", {"resource": resource, **kwargs})

    def dns_chain(self, resource, **kwargs):
        """DNS delegation chain for a resource."""
        return self._request("dns-chain", {"resource": resource, **kwargs})

    def example_resources(self, **kwargs):
        """List example resources for testing."""
        return self._request("example-resources", {**kwargs})

    def historical_whois(self, resource, **kwargs):
        """Historical WHOIS data for a resource."""
        return self._request("historical-whois", {"resource": resource, **kwargs})

    def iana_registry_info(self, resource, **kwargs):
        """IANA registry information for a resource."""
        return self._request("iana-registry-info", {"resource": resource, **kwargs})

    def looking_glass(self, resource, **kwargs):
        """Looking glass data from RIS route collectors."""
        return self._request("looking-glass", {"resource": resource, **kwargs})

    def maxmind_geo_lite(self, resource, **kwargs):
        """MaxMind GeoLite geolocation data."""
        return self._request("maxmind-geo-lite", {"resource": resource, **kwargs})

    def maxmind_geo_lite_announced_by_as(self, resource, **kwargs):
        """MaxMind GeoLite data for prefixes announced by an AS."""
        return self._request("maxmind-geo-lite-announced-by-as", {"resource": resource, **kwargs})

    def network_info(self, resource, **kwargs):
        """Network information (prefix, ASN) for an IP."""
        return self._request("network-info", {"resource": resource, **kwargs})

    def prefix_count(self, resource, **kwargs):
        """Number of prefixes announced by an ASN."""
        return self._request("prefix-count", {"resource": resource, **kwargs})

    def prefix_overview(self, resource, **kwargs):
        """Overview of a prefix (origin ASNs, holder)."""
        return self._request("prefix-overview", {"resource": resource, **kwargs})

    def prefix_routing_consistency(self, resource, **kwargs):
        """Routing consistency for a prefix."""
        return self._request("prefix-routing-consistency", {"resource": resource, **kwargs})

    def prefix_size_distribution(self, resource, **kwargs):
        """Prefix size distribution for an ASN."""
        return self._request("prefix-size-distribution", {"resource": resource, **kwargs})

    def related_prefixes(self, resource, **kwargs):
        """Find related prefixes for a resource."""
        return self._request("related-prefixes", {"resource": resource, **kwargs})

    def reverse_dns(self, resource, **kwargs):
        """Reverse DNS delegations for a prefix."""
        return self._request("reverse-dns", {"resource": resource, **kwargs})

    def reverse_dns_consistency(self, resource, **kwargs):
        """Reverse DNS consistency check."""
        return self._request("reverse-dns-consistency", {"resource": resource, **kwargs})

    def reverse_dns_ip(self, resource, **kwargs):
        """Reverse DNS for a single IP."""
        return self._request("reverse-dns-ip", {"resource": resource, **kwargs})

    def rir(self, resource, **kwargs):
        """RIR responsible for a resource."""
        return self._request("rir", {"resource": resource, **kwargs})

    def rir_geo(self, resource, **kwargs):
        """Geolocation based on RIR allocation data."""
        return self._request("rir-geo", {"resource": resource, **kwargs})

    def rir_prefix_size_distribution(self, resource, **kwargs):
        """RIR-level prefix size distribution."""
        return self._request("rir-prefix-size-distribution", {"resource": resource, **kwargs})

    def rir_stats_country(self, resource, **kwargs):
        """RIR statistics by country."""
        return self._request("rir-stats-country", {"resource": resource, **kwargs})

    def ris_asns(self, **kwargs):
        """List of ASNs seen by RIS."""
        return self._request("ris-asns", {**kwargs})

    def ris_first_last_seen(self, resource, **kwargs):
        """First/last seen dates for a resource in RIS."""
        return self._request("ris-first-last-seen", {"resource": resource, **kwargs})

    def ris_full_table_threshold(self, **kwargs):
        """Current RIS full-table threshold."""
        return self._request("ris-full-table-threshold", {**kwargs})

    def ris_peer_count(self, **kwargs):
        """Number of RIS peers."""
        return self._request("ris-peer-count", {**kwargs})

    def ris_peerings(self, resource, **kwargs):
        """RIS peering information for a resource."""
        return self._request("ris-peerings", {"resource": resource, **kwargs})

    def ris_peers(self, **kwargs):
        """List of RIS peers."""
        return self._request("ris-peers", {**kwargs})

    def ris_prefixes(self, resource, **kwargs):
        """Prefixes seen by RIS for a resource."""
        return self._request("ris-prefixes", {"resource": resource, **kwargs})

    def routing_history(self, resource, **kwargs):
        """Historical routing data for a resource."""
        return self._request("routing-history", {"resource": resource, **kwargs})

    def routing_status(self, resource, **kwargs):
        """Current routing status for a resource."""
        return self._request("routing-status", {"resource": resource, **kwargs})

    def rpki_history(self, resource, **kwargs):
        """RPKI validation history for a resource."""
        return self._request("rpki-history", {"resource": resource, **kwargs})

    def rpki_validation(self, resource, prefix, **kwargs):
        """RPKI validation status for an origin AS + prefix pair."""
        return self._request("rpki-validation", {"resource": resource, "prefix": prefix, **kwargs})

    def rrc_info(self, **kwargs):
        """Information about RIS Route Collectors."""
        return self._request("rrc-info", {**kwargs})

    def searchcomplete(self, resource, **kwargs):
        """Autocomplete/search suggestions for a resource string."""
        return self._request("searchcomplete", {"resource": resource, **kwargs})

    def transfer_history(self, resource, **kwargs):
        """Transfer history for a resource."""
        return self._request("transfer-history", {"resource": resource, **kwargs})

    def visibility(self, resource, **kwargs):
        """Visibility of a resource across RIS peers."""
        return self._request("visibility", {"resource": resource, **kwargs})

    def whats_my_ip(self, **kwargs):
        """Return the caller's IP address."""
        return self._request("whats-my-ip", {**kwargs})

    def whois(self, resource, **kwargs):
        """WHOIS data for a resource."""
        return self._request("whois", {"resource": resource, **kwargs})

    def whois_object_last_updated(self, resource, **kwargs):
        """Last update time of WHOIS objects for a resource."""
        return self._request("whois-object-last-updated", {"resource": resource, **kwargs})

    def zonemaster(self, resource, **kwargs):
        """Zonemaster DNS health check for a domain."""
        return self._request("zonemaster", {"resource": resource, **kwargs})

    # --- Generic / bulk helpers ---

    def query(self, endpoint, **params):
        """Query any endpoint by its slug name with arbitrary parameters."""
        if endpoint not in self.ENDPOINTS:
            logger.warning("Unknown endpoint '%s' -- attempting anyway", endpoint)
        return self._request(endpoint, params)

    def meta(self, endpoint, meta_type="methodology"):
        """Get metadata (methodology/versions/availability) for an endpoint."""
        return self._get_meta(endpoint, meta_type)

    def bulk_query(self, queries, delay=0.1):
        """
        Execute multiple queries concurrently (max 8 parallel per API rules).

        Args:
            queries: List of dicts with keys: endpoint, params (dict)
            delay: Minimum delay between request submissions (seconds)

        Returns:
            List of result dicts in the same order as input queries.
        """
        results = [None] * len(queries)

        def _run(index, endpoint, params):
            time.sleep(index * delay)
            return index, self._request(endpoint, params)

        with ThreadPoolExecutor(max_workers=self.max_concurrent) as executor:
            futures = {
                executor.submit(_run, i, q["endpoint"], q.get("params", {})): i
                for i, q in enumerate(queries)
            }
            for future in as_completed(futures):
                try:
                    idx, result = future.result()
                    results[idx] = result
                except Exception as e:
                    idx = futures[future]
                    results[idx] = {"error": str(e)}

        return results

    def list_endpoints(self):
        """Return list of all known endpoint slugs."""
        return list(self.ENDPOINTS)


# --- CLI usage ---

def main():
    """Interactive CLI demo: query any endpoint."""
    import argparse

    parser = argparse.ArgumentParser(
        description="RIPEstat Data API client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s prefix-overview --resource 193.0.0.0/21
  %(prog)s as-overview --resource AS3333
  %(prog)s routing-status --resource AS13335
  %(prog)s rpki-validation --resource AS13335 --prefix 1.1.1.0/24
  %(prog)s asn-neighbours --resource AS13335
  %(prog)s announced-prefixes --resource AS3333
  %(prog)s visibility --resource 1.1.1.0/24
  %(prog)s bgp-updates --resource 193.0.0.0/21
  %(prog)s looking-glass --resource 1.1.1.0/24
  %(prog)s abuse-contact-finder --resource 8.8.8.8
  %(prog)s whois --resource AS3333
  %(prog)s rpki-history --resource AS13335
  %(prog)s ris-first-last-seen --resource 193.0.0.0/21
  %(prog)s whats-my-ip
  %(prog)s --list-endpoints
  %(prog)s --resource AS13335              (query ALL endpoints for resource)
""",
    )
    parser.add_argument("endpoint", nargs="?", help="Endpoint slug to query")
    parser.add_argument("--resource", "-r", help="Resource to query (IP, prefix, ASN, country)")
    parser.add_argument("--prefix", "-p", help="Prefix (for rpki-validation)")
    parser.add_argument("--starttime", help="Start time (ISO format)")
    parser.add_argument("--endtime", help="End time (ISO format)")
    parser.add_argument("--sourceapp", default="ripestat-cli", help="Source app identifier")
    parser.add_argument("--list-endpoints", action="store_true", help="List all endpoints")
    parser.add_argument("--meta", choices=["methodology", "versions", "availability"],
                        help="Get metadata instead of data")
    parser.add_argument("--raw-json", action="store_true", help="Output raw JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    client = RIPEstat(sourceapp=args.sourceapp)

    if args.list_endpoints:
        print("Available RIPEstat endpoints ({}):\n".format(len(client.ENDPOINTS)))
        for ep in client.ENDPOINTS:
            print("  {}".format(ep))
        return

    if not args.endpoint:
        if not args.resource:
            parser.print_help()
            return
        # Query ALL endpoints for the given resource
        print("Querying all endpoints for resource: {}\n".format(args.resource))
        # Endpoints that don't require a resource parameter
        no_resource = {"example-resources", "ris-asns", "ris-full-table-threshold",
                       "ris-peer-count", "ris-peers", "rrc-info", "whats-my-ip"}
        # rpki-validation needs --prefix too
        skip = {"rpki-validation"}
        endpoints_to_query = [
            ep for ep in client.ENDPOINTS
            if ep not in no_resource and ep not in skip
        ]
        results_all = {}
        for ep in endpoints_to_query:
            params = {"resource": args.resource}
            if args.starttime:
                params["starttime"] = args.starttime
            if args.endtime:
                params["endtime"] = args.endtime
            try:
                result = client.query(ep, **params)
                status = result.get("status", "unknown")
                if status == "ok":
                    results_all[ep] = result.get("data", {})
                    print("[OK]   {}".format(ep))
                else:
                    print("[SKIP] {} - status: {}".format(ep, status))
            except Exception as e:
                print("[FAIL] {} - {}".format(ep, e))
            time.sleep(0.15)  # rate-limit courtesy

        print("\n" + "=" * 60)
        print("Completed: {}/{} endpoints returned data".format(
            len(results_all), len(endpoints_to_query)))
        # Write full results to JSON file
        outfile = "ripestat_{}.json".format(
            args.resource.replace("/", "_").replace(":", "-"))
        with open(outfile, "w") as f_out:
            json.dump(results_all, f_out, indent=2)
        print("Results saved to: {}".format(outfile))
        return

    if args.meta:
        result = client.meta(args.endpoint, args.meta)
    else:
        params = {}
        if args.resource:
            params["resource"] = args.resource
        if args.prefix:
            params["prefix"] = args.prefix
        if args.starttime:
            params["starttime"] = args.starttime
        if args.endtime:
            params["endtime"] = args.endtime
        result = client.query(args.endpoint, **params)

    if args.raw_json:
        print(json.dumps(result, indent=2))
    else:
        # Pretty-print the data section
        if "data" in result:
            print("Endpoint: {}".format(result.get("data_call_name", args.endpoint)))
            print("Status:   {}".format(result.get("status", "unknown")))
            print("Version:  {}".format(result.get("version", "?")))
            print("Cached:   {}".format(result.get("cached", "?")))
            print("-" * 60)
            print(json.dumps(result["data"], indent=2))
        else:
            print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
