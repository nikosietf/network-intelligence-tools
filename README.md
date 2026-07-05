# Network Intelligence Tools

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

A comprehensive collection of Python CLI tools for network intelligence gathering, BGP routing analysis, peering insights, and network operations. Built by network engineers, for network engineers.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Tools Reference](#tools-reference)
  - [RIPEstat Client](#1-ripestat-client)
  - [PeeringDB Client](#2-peeringdb-client)
  - [BGPView Client](#3-bgpview-client)
  - [IRRexplorer Client](#4-irrexplorer-client)
  - [Team Cymru Client](#5-team-cymru-client)
  - [RIPE Atlas Client](#6-ripe-atlas-client)
  - [Cloudflare Radar Client](#7-cloudflare-radar-client)
  - [IX Peering Gaps](#8-ix-peering-gaps)
  - [Remote Tcpdump](#9-remote-tcpdump)
  - [CLI Usage Tracker](#10-cli-usage-tracker)
- [Real-World Use Cases](#real-world-use-cases)
- [Environment Variables](#environment-variables)
- [Output Formats](#output-formats)
- [Architecture](#architecture)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)
- [Author](#author)

---

## Overview

Network Intelligence Tools provides a unified CLI interface to query multiple network intelligence sources and perform network operations tasks. Whether you're investigating a BGP hijack, analyzing peering opportunities, validating RPKI coverage, or troubleshooting device connectivity, these tools streamline your workflow.

### Why This Toolkit?

- **Unified Interface**: Consistent CLI patterns across all tools
- **No Dependencies on Proprietary Systems**: Works with public APIs and standard protocols
- **Automation-Ready**: JSON output for integration with scripts and pipelines
- **Production-Tested**: Battle-tested in large-scale network operations environments
- **Multi-Vendor Support**: Device tools support Juniper, Arista, Nokia, and ArcOS

---

## Features

| Category | Capabilities |
|----------|-------------|
| **BGP Intelligence** | AS relationships, prefix origin validation, routing history, BGP hijack/leak detection |
| **RPKI/IRR Validation** | ROA status, IRR object verification, cross-database consistency checks |
| **Peering Analysis** | IX presence mapping, peer discovery, peering gap identification |
| **Network Measurements** | RIPE Atlas probe queries, traceroute measurements, latency analysis |
| **Device Operations** | Multi-vendor packet capture, commit history analysis, NETCONF vs CLI tracking |
| **IP Attribution** | IP-to-ASN mapping, prefix ownership, geolocation data |

---

## Installation

### Prerequisites

- Python 3.10 or higher
- pip (Python package manager)
- SSH access to network devices (for device operation tools)

### Quick Install

```bash
# Clone the repository
git clone https://github.com/nikosietf/network-intelligence-tools.git
cd network-intelligence-tools

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Verify Installation

```bash
# Test a simple query
python3 ripestat_client.py as-overview --resource AS13335
```

---

## Tools Reference

### 1. RIPEstat Client

**File**: `ripestat_client.py`
**API**: [RIPEstat Data API](https://stat.ripe.net/docs/data_api)
**Authentication**: Not required

Comprehensive client for the RIPEstat Data API, providing access to 30+ endpoints for BGP routing data, WHOIS information, geolocation, abuse contacts, and RPKI validation.

#### Key Features

- BGP routing status and history
- Prefix visibility across Route Information Bases (RIBs)
- RPKI validation status
- AS relationships and neighbors
- Geolocation and network information
- Abuse contact lookups

#### Usage

```bash
# List all available endpoints
python3 ripestat_client.py --list-endpoints

# AS Overview - comprehensive AS information
python3 ripestat_client.py as-overview --resource AS13335

# Routing Status - where a prefix is visible
python3 ripestat_client.py routing-status --resource 1.1.1.0/24

# RPKI Validation - check ROA status
python3 ripestat_client.py rpki-validation --resource AS13335 --prefix 1.1.1.0/24

# BGP State - current BGP announcements
python3 ripestat_client.py bgp-state --resource 1.1.1.0/24

# Looking Glass - real-time BGP data from collectors
python3 ripestat_client.py looking-glass --resource 1.1.1.0/24

# AS Path Length - analyze path lengths to a prefix
python3 ripestat_client.py as-path-length --resource 1.1.1.0/24

# Announced Prefixes - all prefixes announced by an AS
python3 ripestat_client.py announced-prefixes --resource AS13335

# AS Neighbors - upstream and downstream relationships
python3 ripestat_client.py asn-neighbours --resource AS13335

# Abuse Contact - find abuse reporting address
python3 ripestat_client.py abuse-contact-finder --resource 1.1.1.1

# Network Info - WHOIS-based network details
python3 ripestat_client.py network-info --resource 1.1.1.1

# Prefix Overview - comprehensive prefix analysis
python3 ripestat_client.py prefix-overview --resource 1.1.1.0/24

# Historical routing data
python3 ripestat_client.py routing-history --resource 1.1.1.0/24 \
    --starttime 2024-01-01T00:00:00 --endtime 2024-01-31T23:59:59

# JSON output for scripting
python3 ripestat_client.py as-overview --resource AS13335 --raw-json
```

#### All Available Endpoints

| Endpoint | Description |
|----------|-------------|
| `abuse-contact-finder` | Find abuse contact for IP/prefix |
| `address-space-hierarchy` | IP address space hierarchy |
| `address-space-usage` | Address space utilization |
| `announced-prefixes` | Prefixes announced by an AS |
| `as-overview` | Comprehensive AS information |
| `as-path-length` | BGP path length statistics |
| `as-routing-consistency` | Routing consistency analysis |
| `asn-neighbours` | AS neighbor relationships |
| `bgp-state` | Current BGP state |
| `bgp-updates` | BGP update activity |
| `country-asns` | ASNs registered in a country |
| `geoloc` | IP geolocation data |
| `looking-glass` | Real-time BGP looking glass |
| `network-info` | WHOIS network information |
| `prefix-count` | Prefix count for an AS |
| `prefix-overview` | Comprehensive prefix analysis |
| `prefix-routing-consistency` | Prefix routing consistency |
| `prefix-size-distribution` | Prefix size distribution |
| `rir` | Regional Internet Registry info |
| `rir-prefix-size-distribution` | RIR prefix distribution |
| `ris-peers` | RIS peer information |
| `ris-peerings` | RIS peering data |
| `routing-history` | Historical routing data |
| `routing-status` | Current routing status |
| `rpki-validation` | RPKI ROA validation |
| `visibility` | Prefix visibility analysis |
| `whois` | WHOIS data |

---

### 2. PeeringDB Client

**File**: `peeringdb_client.py`
**API**: [PeeringDB API](https://www.peeringdb.com/apidocs/)
**Authentication**: Not required (rate limits apply)

Query the PeeringDB database for network, internet exchange, and facility information. Essential for peering coordination and network planning.

#### Key Features

- Network information and peering policies
- Internet Exchange (IX) details and participants
- Facility (datacenter) information
- Contact information for peering requests

#### Usage

```bash
# Full network information
python3 peeringdb_client.py --asn 13335

# List IXs where an ASN peers
python3 peeringdb_client.py --exchanges-for-asn 13335

# Get IX details by ID
python3 peeringdb_client.py --exchange 1  # DE-CIX Frankfurt

# List all networks at an IX
python3 peeringdb_client.py --networks-at-exchange 1

# Search for facilities
python3 peeringdb_client.py --facility-search "Equinix AM"

# Get facility details
python3 peeringdb_client.py --facility 1

# Networks at a facility
python3 peeringdb_client.py --networks-at-facility 1

# Search networks by name
python3 peeringdb_client.py --network-search "Cloudflare"

# Filter by network type
python3 peeringdb_client.py --networks-at-exchange 1 --type NSP

# JSON output
python3 peeringdb_client.py --asn 13335 --raw-json
```

#### Network Types

| Type | Description |
|------|-------------|
| `NSP` | Network Service Provider |
| `Content` | Content Provider |
| `Enterprise` | Enterprise Network |
| `Educational/Research` | Academic/Research Network |
| `Non-Profit` | Non-Profit Organization |
| `Route Server` | IX Route Server |
| `Cable/DSL/ISP` | Access Provider |

---

### 3. BGPView Client

**File**: `bgpview_client.py`
**API**: [BGPView API](https://bgpview.io/docs)
**Authentication**: Not required

Fast and simple BGP data lookups for ASN information, prefix details, peer relationships, and IP-to-ASN mapping.

#### Usage

```bash
# ASN overview
python3 bgpview_client.py --asn 13335

# ASN prefixes (IPv4 and IPv6)
python3 bgpview_client.py --asn-prefixes 13335

# ASN peers
python3 bgpview_client.py --asn-peers 13335

# ASN upstreams
python3 bgpview_client.py --asn-upstreams 13335

# ASN downstreams
python3 bgpview_client.py --asn-downstreams 13335

# ASN IXs
python3 bgpview_client.py --asn-ixs 13335

# Prefix details
python3 bgpview_client.py --prefix 1.1.1.0/24

# IP lookup
python3 bgpview_client.py --ip 8.8.8.8

# Search by name
python3 bgpview_client.py --search "Cloudflare"

# JSON output
python3 bgpview_client.py --asn 13335 --raw-json
```

---

### 4. IRRexplorer Client

**File**: `irrexplorer_client.py`
**API**: [IRRexplorer](https://irrexplorer.nlnog.net/)
**Authentication**: Not required

Cross-validate routing data against Internet Routing Registry (IRR) databases. Essential for identifying routing security issues, RPKI mismatches, and IRR inconsistencies.

#### Key Features

- IRR vs BGP consistency checking
- RPKI validation status
- Route object verification
- Problem detection (invalid origins, missing objects)

#### Usage

```bash
# Check ASN for routing issues
python3 irrexplorer_client.py --asn 13335

# Show only prefixes with problems
python3 irrexplorer_client.py --asn 13335 --problems-only

# Check specific prefix
python3 irrexplorer_client.py --prefix 1.1.1.0/24

# Detailed prefix analysis
python3 irrexplorer_client.py --prefix 1.1.1.0/24 --verbose

# JSON output
python3 irrexplorer_client.py --asn 13335 --raw-json
```

#### Problem Categories

| Status | Description |
|--------|-------------|
| `VALID` | IRR and BGP match, RPKI valid |
| `INVALID_ORIGIN` | BGP origin doesn't match IRR |
| `NOT_FOUND` | No IRR object for announced prefix |
| `RPKI_INVALID` | RPKI validation failed |
| `RPKI_NOT_FOUND` | No ROA for prefix |

---

### 5. Team Cymru Client

**File**: `team_cymru_client.py`
**API**: [Team Cymru IP to ASN Mapping](https://team-cymru.com/community-services/ip-asn-mapping/)
**Authentication**: Not required

Fast IP-to-ASN mapping using Team Cymru's DNS and WHOIS services. Supports both individual and bulk lookups.

#### Usage

```bash
# Single IP lookup
python3 team_cymru_client.py --ip 8.8.8.8

# Multiple IPs
python3 team_cymru_client.py --bulk-ips 8.8.8.8 1.1.1.1 9.9.9.9

# Bulk lookup from file
python3 team_cymru_client.py --bulk-file ips.txt

# Prefix to ASN (origin AS)
python3 team_cymru_client.py --prefix 1.1.1.0/24

# Use WHOIS instead of DNS (more detailed)
python3 team_cymru_client.py --ip 8.8.8.8 --method whois

# JSON output
python3 team_cymru_client.py --ip 8.8.8.8 --raw-json
```

#### Output Fields

| Field | Description |
|-------|-------------|
| `AS Number` | Origin ASN |
| `BGP Prefix` | Covering BGP prefix |
| `Country` | Country code |
| `Registry` | RIR (ARIN, RIPE, APNIC, etc.) |
| `Allocated` | Allocation date |
| `AS Name` | Organization name |

---

### 6. RIPE Atlas Client

**File**: `ripe_atlas_client.py`
**API**: [RIPE Atlas API](https://atlas.ripe.net/docs/apis/)
**Authentication**: Optional (required for creating measurements)

Query RIPE Atlas probe network and create network measurements. Access to 10,000+ globally distributed probes for ping, traceroute, DNS, and other measurements.

#### Usage

```bash
# List probes in a country
python3 ripe_atlas_client.py --probes-in GB

# List probes in an ASN
python3 ripe_atlas_client.py --probes-for-asn 13335

# Probe details
python3 ripe_atlas_client.py --probe 1

# Get measurement results
python3 ripe_atlas_client.py --measurement 1001

# Active measurements for an ASN
python3 ripe_atlas_client.py --measurements-for-asn 13335

# Create traceroute measurement (requires API key)
export RIPE_ATLAS_KEY="your-api-key"
python3 ripe_atlas_client.py --traceroute-to 1.1.1.1 --from-country GB --count 10

# Create ping measurement
python3 ripe_atlas_client.py --ping-to 8.8.8.8 --from-asn 13335 --count 5

# Create DNS measurement
python3 ripe_atlas_client.py --dns-query example.com --from-country US --count 20

# JSON output
python3 ripe_atlas_client.py --probes-in GB --raw-json
```

#### Probe Selection Options

| Option | Description |
|--------|-------------|
| `--from-country XX` | Select probes from country code |
| `--from-asn NNNN` | Select probes from ASN |
| `--count N` | Number of probes to use |
| `--include-anchors` | Include RIPE Atlas anchors |

---

### 7. Cloudflare Radar Client

**File**: `cloudflare_radar_client.py`
**API**: [Cloudflare Radar API](https://developers.cloudflare.com/radar/)
**Authentication**: Required (API token)

Access Cloudflare's BGP intelligence data, including route leaks, hijack detection, and AS relationship mapping.

#### Setup

```bash
export CLOUDFLARE_API_TOKEN="your-api-token"
```

#### Usage

```bash
# BGP routes for an ASN
python3 cloudflare_radar_client.py --bgp-routes AS13335

# Recent BGP leaks
python3 cloudflare_radar_client.py --bgp-leaks

# Recent BGP hijacks
python3 cloudflare_radar_client.py --bgp-hijacks

# Leaks involving specific ASN
python3 cloudflare_radar_client.py --bgp-leaks --asn 13335

# AS relationships
python3 cloudflare_radar_client.py --as-relationships 13335

# Top ASes by prefix count
python3 cloudflare_radar_client.py --top-ases

# BGP route stats
python3 cloudflare_radar_client.py --bgp-stats

# Time-based filtering
python3 cloudflare_radar_client.py --bgp-leaks --since 24h

# JSON output
python3 cloudflare_radar_client.py --bgp-routes AS13335 --raw-json
```

---

### 8. IX Peering Gaps

**File**: `ix_peering_gaps.py`
**Data Source**: PeeringDB
**Authentication**: Not required

Identify peering opportunities by finding networks present at shared Internet Exchanges where you don't currently peer.

#### Key Features

- Identify potential peers at shared IXs
- Filter by network type and port speed
- Rank opportunities by presence overlap
- Export results for peering team follow-up

#### Usage

```bash
# Find peering gaps for your ASN
python3 ix_peering_gaps.py --asn 13335

# Top 20 opportunities
python3 ix_peering_gaps.py --asn 13335 --top 20

# Filter by network type
python3 ix_peering_gaps.py --asn 13335 --type NSP
python3 ix_peering_gaps.py --asn 13335 --type Content

# Minimum port speed (Mbps)
python3 ix_peering_gaps.py --asn 13335 --min-speed 10000

# Specific IX only
python3 ix_peering_gaps.py --asn 13335 --ix "DE-CIX Frankfurt"

# Exclude already-peered networks (provide list)
python3 ix_peering_gaps.py --asn 13335 --exclude-peers peers.txt

# JSON output
python3 ix_peering_gaps.py --asn 13335 --raw-json

# CSV export for spreadsheet analysis
python3 ix_peering_gaps.py --asn 13335 --output-csv gaps.csv
```

#### Output Fields

| Field | Description |
|-------|-------------|
| `ASN` | Potential peer ASN |
| `Network Name` | Organization name |
| `Type` | Network type (NSP, Content, etc.) |
| `Shared IXs` | Number of shared IX presence |
| `IXs` | List of shared IXs |
| `Max Speed` | Largest port at shared IXs |

---

### 9. Remote Tcpdump

**File**: `remote_tcpdump.py`
**Protocol**: SSH
**Authentication**: Required (SSH credentials)

Multi-vendor remote packet capture tool supporting Juniper (JunOS), Arista (EOS), Nokia (SROS), and ArcOS devices. Automates the entire capture workflow including interface discovery, capture execution, and pcap transfer.

#### Supported Platforms

| Vendor | Method | Transfer |
|--------|--------|----------|
| Juniper (JunOS) | `monitor traffic` | Base64 via SSH |
| Arista (EOS) | `tcpdump` in bash | Base64 via SSH |
| Nokia (SROS) | `mirror/pcap` | SFTP |
| ArcOS (Arrcus) | `tcpdump` in bash | Base64 via SSH |

#### Key Features

- Auto-detect vendor from hostname
- Discover loopback/system IP automatically
- List ISIS/OSPF interfaces with peer information
- Filter by protocol, port, or host
- Automatic cleanup of remote files
- Interactive capture with countdown

#### Setup

```bash
# Option 1: Environment variables
export DEVICE_USERNAME="admin"
export DEVICE_PASSWORD="password"

# Option 2: .env file
echo "DEVICE_USERNAME=admin" >> .env
echo "DEVICE_PASSWORD=password" >> .env
```

#### Usage

```bash
# Show available interfaces
python3 remote_tcpdump.py -d router1.example.com --show-interfaces

# Basic capture (60 seconds on loopback)
python3 remote_tcpdump.py -d router1.example.com

# Capture on specific interface
python3 remote_tcpdump.py -d router1.example.com --interface ae0.0

# Capture ISIS traffic on specific interface
python3 remote_tcpdump.py -d router1.example.com --isis-interface ae15.0

# Capture OSPF traffic (Arista)
python3 remote_tcpdump.py -d switch1.example.com --ospf-interface Ethernet1/1

# Filter by port (e.g., BGP)
python3 remote_tcpdump.py -d router1.example.com --port 179

# Filter by protocol
python3 remote_tcpdump.py -d router1.example.com --protocol icmp

# Custom duration
python3 remote_tcpdump.py -d router1.example.com --duration 300

# Headers only (smaller pcap)
python3 remote_tcpdump.py -d router1.example.com --snap-len 96

# Custom output filename
python3 remote_tcpdump.py -d router1.example.com --output capture.pcap

# Override vendor detection
python3 remote_tcpdump.py -d device.example.com --vendor juniper

# Nokia: capture on specific port
python3 remote_tcpdump.py -d nokia-router.example.com --interface 1/1/c1/1
```

#### CLI Options

| Option | Default | Description |
|--------|---------|-------------|
| `-d, --device` | Required | Device hostname |
| `-u, --username` | `$DEVICE_USERNAME` | SSH username |
| `-p, --password` | `$DEVICE_PASSWORD` | SSH password |
| `--vendor` | Auto-detect | Force vendor: `juniper`, `arista`, `nokia`, `arcos` |
| `--interface` | `any` or `lo0.0` | Capture interface |
| `--duration` | `60` | Capture duration (seconds) |
| `--port` | None | Filter by port number |
| `--protocol` | None | Filter by protocol |
| `--snap-len` | `0` (full) | Packet snap length |
| `--output` | `{device}.pcap` | Output filename |
| `--show-interfaces` | False | List interfaces and exit |
| `--isis-interface` | None | Capture ISIS on specific interface |
| `--ospf-interface` | None | Capture OSPF on specific interface |

---

### 10. CLI Usage Tracker

**File**: `cli_usage_tracker.py`
**Protocol**: SSH/NETCONF
**Authentication**: Required (SSH credentials)

Analyze commit history across network devices to track CLI vs NETCONF usage. Identifies manual CLI changes that may indicate configuration drift or process violations.

#### Supported Platforms

| Vendor | Method | Data Source |
|--------|--------|-------------|
| Juniper (JunOS) | NETCONF | `<get-commit-information>` |
| Nokia (SROS) | NETCONF | YANG commit-history |
| ArcOS (Arrcus) | NETCONF | commit-list query |

#### Key Features

- Pull device list from ISIS dynamically
- Per-device and per-user commit analysis
- CLI vs NETCONF breakdown
- HTML, CSV, and JSON report generation
- Fleet-wide statistics and trends

#### Setup

```bash
# Environment variables
export DEVICE_USERNAME="admin"
export DEVICE_PASSWORD="password"

# Or use .env file
echo "DEVICE_USERNAME=admin" >> .env
echo "DEVICE_PASSWORD=password" >> .env
```

#### Usage

```bash
# Discover devices from ISIS and analyze
python3 cli_usage_tracker.py --from-isis

# Use specific ISIS router
python3 cli_usage_tracker.py --from-isis --isis-router core-rtr.example.com

# Analyze specific devices
python3 cli_usage_tracker.py --devices router1,router2,switch1

# Use inventory file
python3 cli_usage_tracker.py --inventory devices.csv

# Filter by vendor
python3 cli_usage_tracker.py --from-isis --vendor Juniper
python3 cli_usage_tracker.py --from-isis --vendor Nokia

# Limit commits per device
python3 cli_usage_tracker.py --from-isis --max-commits 50

# Custom output directory
python3 cli_usage_tracker.py --from-isis --output-dir ./reports

# Increase concurrency
python3 cli_usage_tracker.py --from-isis --concurrency 20
```

#### CLI Options

| Option | Default | Description |
|--------|---------|-------------|
| `--from-isis` | False | Discover devices from ISIS LSDB |
| `--isis-router` | `isis-router.lab` | Router for ISIS discovery |
| `--devices` | None | Comma-separated device list |
| `--inventory` | None | CSV/Excel inventory file |
| `--vendor` | All | Filter by vendor |
| `--max-commits` | `100` | Max commits per device |
| `--concurrency` | `10` | Parallel device connections |
| `--output-dir` | `.` | Report output directory |
| `--env-file` | `.env` | Credentials file path |

#### Output Reports

| File | Description |
|------|-------------|
| `cli_usage_report_*.html` | Interactive HTML report |
| `cli_usage_report_*.csv` | Raw data for analysis |
| `cli_usage_summary_*.txt` | Executive summary |
| `cli_usage_cli_only_*.txt` | CLI-only commits (violations) |

---

## Real-World Use Cases

### 1. BGP Hijack Investigation

When you suspect a prefix hijack:

```bash
# Check current routing status
python3 ripestat_client.py routing-status --resource 203.0.113.0/24

# Verify RPKI status
python3 ripestat_client.py rpki-validation --resource AS64496 --prefix 203.0.113.0/24

# Check IRR consistency
python3 irrexplorer_client.py --prefix 203.0.113.0/24

# Look for recent BGP hijacks
python3 cloudflare_radar_client.py --bgp-hijacks --since 24h

# Historical routing data
python3 ripestat_client.py routing-history --resource 203.0.113.0/24 \
    --starttime 2024-01-01T00:00:00 --endtime 2024-01-02T00:00:00
```

### 2. Peering Expansion Planning

Identify and validate potential peers:

```bash
# Find peering opportunities
python3 ix_peering_gaps.py --asn 64496 --type NSP --top 20

# Research potential peer
python3 peeringdb_client.py --asn 64497

# Check their routing hygiene
python3 irrexplorer_client.py --asn 64497 --problems-only

# Verify their RPKI deployment
python3 ripestat_client.py announced-prefixes --resource AS64497 | \
    xargs -I {} python3 ripestat_client.py rpki-validation --resource AS64497 --prefix {}
```

### 3. IP Address Investigation

Trace ownership of suspicious IPs:

```bash
# Quick attribution
python3 team_cymru_client.py --ip 192.0.2.1

# Detailed lookup
python3 bgpview_client.py --ip 192.0.2.1

# Abuse contact
python3 ripestat_client.py abuse-contact-finder --resource 192.0.2.1

# Network information
python3 ripestat_client.py network-info --resource 192.0.2.1

# Bulk investigation
python3 team_cymru_client.py --bulk-file suspicious_ips.txt
```

### 4. Network Troubleshooting

Capture and analyze traffic:

```bash
# List available interfaces
python3 remote_tcpdump.py -d router.example.com --show-interfaces

# Capture BGP session
python3 remote_tcpdump.py -d router.example.com --port 179 --duration 120

# Analyze ISIS adjacency
python3 remote_tcpdump.py -d router.example.com --isis-interface ae0.0

# Open capture in Wireshark
wireshark router.example.com.pcap
```

### 5. Configuration Compliance Audit

Track manual changes:

```bash
# Run fleet-wide analysis
python3 cli_usage_tracker.py --from-isis --output-dir ./audit

# Review CLI-only commits
cat ./audit/cli_usage_cli_only_*.txt

# Check specific devices
python3 cli_usage_tracker.py --devices core1,core2,edge1 --max-commits 200
```

---

## Environment Variables

| Variable | Tools | Description |
|----------|-------|-------------|
| `RIPE_ATLAS_KEY` | `ripe_atlas_client.py` | RIPE Atlas API key for creating measurements |
| `CLOUDFLARE_API_TOKEN` | `cloudflare_radar_client.py` | Cloudflare API token (Bearer auth) |
| `CLOUDFLARE_API_KEY` | `cloudflare_radar_client.py` | Alternative: Global API key |
| `CLOUDFLARE_EMAIL` | `cloudflare_radar_client.py` | Email for API key auth |
| `DEVICE_USERNAME` | `remote_tcpdump.py`, `cli_usage_tracker.py` | SSH username |
| `DEVICE_PASSWORD` | `remote_tcpdump.py`, `cli_usage_tracker.py` | SSH password |

### Using .env Files

Create a `.env` file in the working directory:

```bash
# API Keys
RIPE_ATLAS_KEY=your-atlas-key
CLOUDFLARE_API_TOKEN=your-cloudflare-token

# Device Credentials
DEVICE_USERNAME=admin
DEVICE_PASSWORD=secret
```

---

## Output Formats

All tools support multiple output formats:

| Format | Flag | Use Case |
|--------|------|----------|
| Human-readable | (default) | Interactive use |
| JSON | `--raw-json` | Scripting, pipelines |
| CSV | `--output-csv file.csv` | Spreadsheet analysis |

### JSON Output Example

```bash
# Pipe to jq for processing
python3 ripestat_client.py as-overview --resource AS13335 --raw-json | \
    jq '.data.holder'

# Save to file
python3 peeringdb_client.py --asn 13335 --raw-json > cloudflare_pdb.json
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Network Intelligence Tools                   │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │  RIPEstat   │  │  PeeringDB  │  │   BGPView   │             │
│  │   Client    │  │   Client    │  │   Client    │  ... APIs   │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘             │
│         │                │                │                     │
│         ▼                ▼                ▼                     │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    HTTP / REST Layer                        ││
│  │              (requests, response parsing)                   ││
│  └─────────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐                              │
│  │   Remote    │  │ CLI Usage   │                              │
│  │   Tcpdump   │  │  Tracker    │  ... Device Tools            │
│  └──────┬──────┘  └──────┬──────┘                              │
│         │                │                                      │
│         ▼                ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                  SSH / NETCONF Layer                        ││
│  │         (netmiko, paramiko, ncclient, scrapli)              ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Target Systems                               │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐            │
│  │ Public  │  │ Network │  │ Network │  │ Network │            │
│  │  APIs   │  │ Devices │  │ Devices │  │ Devices │            │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘            │
└─────────────────────────────────────────────────────────────────┘
```

---

## Troubleshooting

### API Tools

| Issue | Solution |
|-------|----------|
| `Connection timeout` | Check network connectivity; some APIs may be geo-restricted |
| `Rate limited (429)` | Reduce request frequency; implement backoff |
| `SSL certificate error` | Update CA certificates: `pip install --upgrade certifi` |
| `JSON decode error` | API may be returning HTML error page; check URL |

### Device Tools

| Issue | Solution |
|-------|----------|
| `SSH connection refused` | Verify SSH is enabled; check ACLs and firewall |
| `Authentication failed` | Verify credentials; check if account is locked |
| `NETCONF not available` | Enable NETCONF on device; check port 830/22 |
| `Permission denied` | User may lack required privileges |
| `Timeout during capture` | Reduce duration; check for session limits |
| `Base64 decode error` | Large capture; reduce duration or snap-length |

### General

```bash
# Verbose output for debugging
python3 tool.py [args] --verbose

# Check Python version
python3 --version  # Requires 3.10+

# Verify dependencies
pip list | grep -E "requests|netmiko|paramiko|ncclient"

# Test network connectivity
curl -I https://stat.ripe.net/
```

---

## Contributing

Contributions are welcome! Please follow these guidelines:

### Code Standards

- Python 3.10+ with type hints
- Use `from __future__ import annotations`
- Follow existing code style
- Include docstrings with usage examples
- Add CLI help text for all arguments

### Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests and linting
5. Commit with clear messages
6. Push to your fork
7. Open a Pull Request

### Guidelines

- **No proprietary data**: Use public examples (AS13335, AS3333, etc.)
- **No hardcoded credentials**: Use environment variables
- **Test thoroughly**: Verify against public APIs/lab devices
- **Document changes**: Update README for new features

---

## License

MIT License

Copyright (c) 2024 Nikos Leontsinis

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

## Author

**Nikos Leontsinis**

- GitHub: [@nikosietf](https://github.com/nikosietf)

---

## Acknowledgments

### APIs and Data Sources

- [RIPEstat](https://stat.ripe.net/) - RIPE NCC's comprehensive routing data API
- [PeeringDB](https://www.peeringdb.com/) - The interconnection database
- [BGPView](https://bgpview.io/) - BGP routing information
- [IRRexplorer](https://irrexplorer.nlnog.net/) - NLNOG's IRR validation tool
- [Team Cymru](https://team-cymru.com/) - IP-to-ASN mapping services
- [RIPE Atlas](https://atlas.ripe.net/) - Global network measurement platform
- [Cloudflare Radar](https://radar.cloudflare.com/) - Internet intelligence

### Libraries

- [requests](https://requests.readthedocs.io/) - HTTP library
- [netmiko](https://github.com/ktbyers/netmiko) - Multi-vendor SSH library
- [ncclient](https://github.com/ncclient/ncclient) - NETCONF client
- [paramiko](https://www.paramiko.org/) - SSH implementation
- [scrapli](https://github.com/carlmontanari/scrapli) - Screen scraping library

---

*Built with dedication for the network engineering community.*
