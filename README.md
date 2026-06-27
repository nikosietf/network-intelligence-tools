# Network Intelligence Tools

A collection of Python CLI tools for network intelligence gathering, BGP analysis, and peering insights. These tools interface with public APIs to provide routing information, IRR/RPKI validation, and peering database lookups.

## Tools

| Tool | Description | API Key Required |
|------|-------------|------------------|
| `ripestat_client.py` | Comprehensive RIPEstat Data API client for BGP, WHOIS, geolocation, RPKI validation | No |
| `peeringdb_client.py` | PeeringDB API client for network/IX/facility information | No |
| `bgpview_client.py` | BGPView API client for ASN, prefix, and peer lookups | No |
| `irrexplorer_client.py` | IRRexplorer API client for IRR/BGP/RPKI cross-validation | No |
| `team_cymru_client.py` | Team Cymru IP-to-ASN mapping via DNS and whois | No |
| `ripe_atlas_client.py` | RIPE Atlas API client for network measurements | Optional* |
| `cloudflare_radar_client.py` | Cloudflare Radar API client for BGP intelligence | Yes |
| `ix_peering_gaps.py` | Identify peering opportunities at shared IXs | No |

\* Read-only queries work without API key. Creating measurements requires one.

## Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/network-intelligence-tools.git
cd network-intelligence-tools

# Install dependencies
pip install -r requirements.txt
```

## Quick Start

### RIPEstat - BGP and Routing Data

```bash
# Get AS overview
python3 ripestat_client.py as-overview --resource AS13335

# Check prefix routing status
python3 ripestat_client.py routing-status --resource 1.1.1.0/24

# RPKI validation
python3 ripestat_client.py rpki-validation --resource AS13335 --prefix 1.1.1.0/24

# List all available endpoints
python3 ripestat_client.py --list-endpoints
```

### PeeringDB - Network and IX Information

```bash
# Full network info
python3 peeringdb_client.py --asn 13335

# List IXs where an ASN peers
python3 peeringdb_client.py --exchanges-for-asn 13335

# Search for facilities
python3 peeringdb_client.py --facility-search "Equinix AM"
```

### IRRexplorer - IRR/RPKI Validation

```bash
# Check ASN prefixes for issues
python3 irrexplorer_client.py --asn 13335 --problems-only

# Check specific prefix
python3 irrexplorer_client.py --prefix 1.1.1.0/24
```

### BGPView - ASN and Prefix Lookups

```bash
# ASN overview
python3 bgpview_client.py --asn 13335

# ASN prefixes
python3 bgpview_client.py --asn-prefixes 13335

# ASN peers and upstreams
python3 bgpview_client.py --asn-peers 13335
python3 bgpview_client.py --asn-upstreams 13335
```

### Team Cymru - IP-to-ASN Mapping

```bash
# Single IP lookup
python3 team_cymru_client.py --ip 8.8.8.8

# Bulk lookup
python3 team_cymru_client.py --bulk-ips 8.8.8.8 1.1.1.1 9.9.9.9

# Prefix to ASN
python3 team_cymru_client.py --prefix 1.1.1.0/24
```

### RIPE Atlas - Network Measurements

```bash
# List probes in a country
python3 ripe_atlas_client.py --probes-in GB

# List probes in an ASN
python3 ripe_atlas_client.py --probes-for-asn 13335

# Create traceroute measurement (requires API key)
export RIPE_ATLAS_KEY="your-api-key"
python3 ripe_atlas_client.py --traceroute-to 1.1.1.1 --from-country GB --count 5
```

### Cloudflare Radar - BGP Intelligence

```bash
export CLOUDFLARE_API_TOKEN="your-api-token"

# BGP routes for ASN
python3 cloudflare_radar_client.py --bgp-routes AS13335

# Recent BGP leaks and hijacks
python3 cloudflare_radar_client.py --bgp-leaks
python3 cloudflare_radar_client.py --bgp-hijacks

# AS relationships
python3 cloudflare_radar_client.py --as-relationships 13335
```

### IX Peering Gaps - Peering Opportunities

```bash
# Find carriers at shared IXs
python3 ix_peering_gaps.py --asn 13335

# Filter by network type and port speed
python3 ix_peering_gaps.py --asn 13335 --type NSP --min-speed 10000
```

## Environment Variables

| Variable | Tool | Description |
|----------|------|-------------|
| `RIPE_ATLAS_KEY` | ripe_atlas_client.py | RIPE Atlas API key for creating measurements |
| `CLOUDFLARE_API_TOKEN` | cloudflare_radar_client.py | Cloudflare API token |
| `CLOUDFLARE_API_KEY` | cloudflare_radar_client.py | Alternative: Cloudflare API key |
| `CLOUDFLARE_EMAIL` | cloudflare_radar_client.py | Alternative: Cloudflare account email |

## Output Formats

All tools support:
- Human-readable formatted output (default)
- JSON output with `--raw-json` flag

## Use Cases

### Peering Analysis
```bash
# 1. Get network's IX presence
python3 peeringdb_client.py --exchanges-for-asn 13335

# 2. Find potential peers at shared IXs
python3 ix_peering_gaps.py --asn 13335 --top 20

# 3. Check potential peer's routing hygiene
python3 irrexplorer_client.py --asn 174 --problems-only
```

### Prefix Investigation
```bash
# Check a prefix across multiple sources
python3 ripestat_client.py prefix-overview --resource 1.1.1.0/24
python3 bgpview_client.py --prefix 1.1.1.0/24
python3 irrexplorer_client.py --prefix 1.1.1.0/24
```

### IP Attribution
```bash
# Single IP
python3 team_cymru_client.py --ip 8.8.8.8
python3 bgpview_client.py --ip 8.8.8.8

# Bulk from file
python3 team_cymru_client.py --bulk-file suspicious_ips.txt
```

## Contributing

Contributions welcome! Please ensure:
- No hardcoded credentials or company-specific data
- Use generic examples (AS13335/Cloudflare, AS3333/RIPE NCC)
- Include docstrings and CLI help text

## License

MIT License - see individual files for details.

## Author

Nikos Leontsinis

## Acknowledgments

These tools interface with the following public APIs:
- [RIPEstat](https://stat.ripe.net/)
- [PeeringDB](https://www.peeringdb.com/)
- [BGPView](https://bgpview.io/)
- [IRRexplorer](https://irrexplorer.nlnog.net/)
- [Team Cymru](https://team-cymru.com/)
- [RIPE Atlas](https://atlas.ripe.net/)
- [Cloudflare Radar](https://radar.cloudflare.com/)
