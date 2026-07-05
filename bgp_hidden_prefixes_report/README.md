# BGP Hidden Prefixes Report

Collects and reports BGP hidden (rejected) prefixes from Juniper routers via NETCONF/PyEZ.

## Overview

In Junos, a **hidden route** is a BGP route that was received but NOT installed in the routing table because it failed validation. These routes are kept in memory for debugging purposes. This script collects all hidden prefixes across your Juniper router fleet and reports why each prefix is being rejected.

## Requirements

```bash
pip install junos-eznc lxml
```

## Usage

### Basic Usage

```bash
# Single router
python3 bgp_hidden_prefixes_report.py --hosts bor01.am3.eu.equinix.net

# Multiple routers (comma-separated)
python3 bgp_hidden_prefixes_report.py --hosts bor01.am3.eu.equinix.net,bor01.fr2.eu.equinix.net

# From a file (one hostname per line)
python3 bgp_hidden_prefixes_report.py --hosts-file routers.txt
```

### With Options

```bash
python3 bgp_hidden_prefixes_report.py \
    --hosts-file routers.txt \
    --workers 10 \
    --port 22 \
    --timeout 60 \
    --output-prefix bgp_hidden_prefixes_bor_ecgw
```

### Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--hosts` | Comma-separated list of router hostnames/IPs | - |
| `--hosts-file` | File containing hostnames (one per line) | - |
| `--username` | SSH username | `$DEVICE_USERNAME` / `$JUNOS_USERNAME` / current user |
| `--password` | SSH password | `$DEVICE_PASSWORD` / `$JUNOS_PASSWORD` |
| `--ssh-key` | Path to SSH private key | `$JUNOS_SSH_KEY` |
| `--port` | NETCONF/SSH port | 22 |
| `--timeout` | Connection timeout (seconds) | 60 |
| `--workers` | Number of parallel connections | 5 |
| `--output-prefix` | Output filename prefix | `bgp_hidden_prefixes_report` |
| `--no-csv` | Skip CSV output | false |
| `--no-json` | Skip JSON output | false |

### Environment Variables

```bash
export DEVICE_USERNAME="your_username"
export DEVICE_PASSWORD="your_password"
# Or use SSH keys (recommended)
export JUNOS_SSH_KEY="~/.ssh/id_rsa"
```

## Output Files

The script generates two output files with timestamps:

### CSV Report
`bgp_hidden_prefixes_report_YYYYMMDD_HHMMSS.csv`

| Column | Description |
|--------|-------------|
| Router | Router hostname |
| Timestamp | Collection timestamp (UTC) |
| Neighbor | BGP peer IP address |
| Neighbor_AS | BGP peer AS number |
| Neighbor_Description | Peer description from config |
| Prefix | Hidden prefix |
| Prefix_Length | CIDR prefix length |
| Next_Hop | Protocol next-hop |
| Local_Preference | BGP local preference |
| MED | Multi-Exit Discriminator |
| AS_Path | Full AS path |
| Origin | Origin attribute (IGP/EGP/Incomplete) |
| Communities | BGP communities (pipe-separated) |
| Validation_State | RPKI validation state |
| Hidden_Reason | Why the prefix is hidden |

### JSON Report
`bgp_hidden_prefixes_report_YYYYMMDD_HHMMSS.json`

Structured report with full details including summary statistics.

## How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│  1. Connect to router via NETCONF (PyEZ)                           │
│     └─ Device(host=router, user=username, port=22)                 │
│                                                                     │
│  2. Get BGP Summary                                                 │
│     └─ RPC: get_bgp_summary_information()                          │
│     └─ CLI equivalent: show bgp summary                            │
│                                                                     │
│  3. For each ESTABLISHED peer:                                      │
│     └─ RPC: get_route_information(                                 │
│              protocol="bgp",                                        │
│              peer=<peer_ip>,                                        │
│              hidden=True,        ← Only hidden routes               │
│              extensive=True      ← Detailed attributes              │
│          )                                                          │
│     └─ CLI equivalent: show route receive-protocol bgp <peer>      │
│                        hidden extensive                             │
│                                                                     │
│  4. Parse XML response to extract prefix details and hidden reason │
│                                                                     │
│  5. Aggregate results and generate CSV/JSON reports                │
└─────────────────────────────────────────────────────────────────────┘
```

## Hidden Reasons

Common reasons why prefixes are hidden:

| Reason | Description |
|--------|-------------|
| `Unusable path` | Next-hop unreachable, or path attributes invalid |
| `Unknown (hidden by policy or not-best)` | Rejected by import routing policy |
| `Community: no-export` | Has no-export community |
| `RPKI: invalid` | RPKI validation failed (origin AS invalid) |
| `RPKI: unknown` | No RPKI ROA data available |
| `Not best path` | Lost to a better route (tie-breaker) |
| `Marked as hidden` | Explicitly hidden by policy |

## Example Output

### Console Output
```
[bor01.am3.eu.equinix.net] Connecting via NETCONF...
[bor01.am3.eu.equinix.net] Retrieving BGP summary...
[bor01.am3.eu.equinix.net] Found 450 BGP peers
[bor01.am3.eu.equinix.net] Checking hidden prefixes from 80.249.208.34...
[bor01.am3.eu.equinix.net]   -> 42 hidden prefixes from 80.249.208.34
[bor01.am3.eu.equinix.net] Skipping peer 80.249.208.50 (state: Active)
...
[bor01.am3.eu.equinix.net] Complete: 5605 hidden prefixes from 16 peers

================================================================================
BGP HIDDEN PREFIXES REPORT SUMMARY
================================================================================

bor01.am3.eu.equinix.net: OK
  BGP Peers: 450
  Peers with hidden prefixes: 16
  Total hidden prefixes: 5605
  Top hidden reasons:
    - Unusable path: 3200
    - Unknown (hidden by policy or not-best): 1800
    - Community: no-export: 605

--------------------------------------------------------------------------------
TOTAL: 5605 hidden prefixes from 16 peers across 1 routers
================================================================================
```

### CSV Output Example
```csv
Router,Neighbor,Neighbor_AS,Prefix,Prefix_Length,Hidden_Reason
bor01.am3.eu.equinix.net,80.249.208.34,1103,195.169.142.0,32,Unusable path
bor01.am3.eu.equinix.net,80.249.208.43,2611,91.209.236.0,32,Community: no-export
```

## Use Cases

1. **Routing Policy Audit** - Identify prefixes being filtered unexpectedly
2. **RPKI Monitoring** - Track RPKI invalid/unknown routes
3. **Peering Health** - Find peers with high hidden prefix counts
4. **Troubleshooting** - Debug why specific prefixes aren't being accepted
5. **Compliance** - Document routing hygiene across the network

## Performance

- Uses parallel workers (default: 5) for concurrent router collection
- Large peering routers (300+ peers) may take 30-60 minutes per router
- Recommended: `--workers 10` for large deployments
- RPC timeouts are handled gracefully (peer skipped, continues to next)

## Troubleshooting

### Connection Errors
```
[router] ERROR: Connection failed: ConnectError
```
- Check hostname resolution
- Verify NETCONF is enabled: `set system services netconf ssh`
- Check port (default 22, some use 830)

### Authentication Errors
```
[router] ERROR: Authentication failed
```
- Verify username/password or SSH key
- Check user permissions on router

### RPC Timeouts
```
[router] Warning: RPC error for peer X.X.X.X: RpcTimeoutError
```
- Normal for peers with very large routing tables
- Increase `--timeout` if needed
- Peer is skipped, script continues

## Author

NEO Engineering Team

## Related

- Junos PyEZ Documentation: https://junos-pyez.readthedocs.io/
- RPKI/ROV: RFC 6811, RFC 8893
