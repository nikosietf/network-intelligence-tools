#!/usr/bin/env python3
"""Remote tcpdump/monitor-traffic/pcap capture on ArcOS, Juniper, Arista, and Nokia devices.

Uses netmiko for SSH session management (handles prompts, pagination, vendor detection).
Uses paramiko channel for the interactive capture portion (Ctrl+C to stop).
Uses scrapli for Nokia SROS (MD-CLI support).

Supported vendors:
  - ArcOS (Arrcus): SSH -> CLI -> bash -> sudo -> tcpdump -> base64 transfer
  - Juniper (JunOS): SSH -> CLI -> monitor traffic -> start shell -> base64 transfer
  - Arista (EOS): SSH -> CLI -> bash -> tcpdump -> base64 transfer
  - Nokia (SROS): SSH -> MD-CLI -> mirror/pcap -> SFTP transfer

Usage examples:
  # Auto-detect vendor, capture loopback traffic
  python3 remote_tcpdump.py -d router1.lab
  python3 remote_tcpdump.py -d switch1.dc1
  python3 remote_tcpdump.py -d nokia-sr1.dc1

  # Show ISIS interfaces
  python3 remote_tcpdump.py -d router1.lab --show-interfaces

  # Capture on a specific ISIS interface
  python3 remote_tcpdump.py -d router1.lab --isis-interface ae15.0
  python3 remote_tcpdump.py -d switch1.dc1 --isis-interface bond35

  # Nokia capture on specific port
  python3 remote_tcpdump.py -d nokia-sr1.dc1 --interface 1/1/c1/1 --duration 60

  # Explicit vendor override
  python3 remote_tcpdump.py -d myrouter --vendor juniper
  python3 remote_tcpdump.py -d myswitch --vendor nokia

  # With options
  python3 remote_tcpdump.py -d router1.lab --duration 300 --port 179
  python3 remote_tcpdump.py -d switch1.dc1 --snap-len 96 --exclude-port 22
"""

import argparse, getpass, os, sys, time, re, base64, socket, subprocess
from pathlib import Path
from netmiko import ConnectHandler
import paramiko
import pexpect

# Optional: scrapli for Nokia SROS
try:
    from scrapli import Scrapli
    SCRAPLI_AVAILABLE = True
except ImportError:
    SCRAPLI_AVAILABLE = False


def load_dotenv(path=None):
    """Load .env file into os.environ."""
    if path is None:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.isfile(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, _, value = line.partition("=")
            os.environ[key.strip()] = value.strip()


# ============================================================
# Vendor-specific device type mapping for netmiko
# ============================================================

VENDOR_MAP = {
    "juniper": "juniper_junos",
    "arcos": "linux",  # ArcOS CLI is close enough; we'll use send_command with expect
    "arista": "arista_eos",
    "nokia": "nokia_sros",  # Uses scrapli instead of netmiko
}


def detect_vendor_from_hostname(hostname):
    """Heuristic vendor detection based on hostname prefix patterns."""
    prefix = hostname.split(".")[0] if "." in hostname else hostname
    # Strip trailing digits
    role = re.sub(r"\d+$", "", prefix)

    # Nokia patterns: 7750, sr (service router), etc.
    # Customize these patterns for your environment
    if "7750" in hostname or "sros" in hostname.lower() or role in ("sr", "sar"):
        return "nokia"
    # Juniper patterns: common router role prefixes
    if role in ("rtr", "rt", "rr", "pr", "cr", "pe", "p", "mx", "ptx", "qfx"):
        return "juniper"
    # ArcOS patterns
    if role in ("arc", "arcos") or "arrcus" in hostname.lower():
        return "arcos"
    # Arista patterns: common switch prefixes
    if role in ("sw", "csw", "lsw", "dsw", "asw", "leaf", "spine"):
        return "arista"
    return None


# ============================================================
# Interactive shell helper (paramiko channel)
# ============================================================

def read_until(channel, patterns, timeout=30):
    """Read channel output until one of the patterns matches. Returns (output, match_index)."""
    output = ""
    start = time.time()
    while time.time() - start < timeout:
        if channel.recv_ready():
            chunk = channel.recv(65535).decode(errors="replace")
            output += chunk
            for i, pat in enumerate(patterns):
                if re.search(pat, output):
                    return output, i
        else:
            time.sleep(0.2)
    return output, -1  # timeout


def send_and_wait(channel, command, patterns, timeout=30):
    """Send a command and wait for a prompt pattern."""
    channel.send(command + "\n")
    return read_until(channel, patterns, timeout)


# ============================================================
# ArcOS functions
# ============================================================

def discover_loopback_ip_arcos(net_connect):
    output = net_connect.send_command("show running-config interface loopback0")
    match = re.search(r"ipv4 address\s+(\d+\.\d+\.\d+\.\d+)", output)
    return match.group(1) if match else None


def discover_isis_interfaces_arcos(net_connect):
    isis_output = net_connect.send_command("show isis interface")
    interfaces = {}
    for line in isis_output.split("\n"):
        line = line.strip()
        if not line or line.startswith("INTERFACE") or line.startswith("-"):
            continue
        parts = line.split()
        if parts and parts[0].startswith(("swp", "bond", "eth", "ae", "ge-", "xe-", "et-")):
            interfaces[parts[0]] = {"ip": None, "description": "", "peer": ""}

    for iface in list(interfaces.keys()):
        iface_output = net_connect.send_command(f"show running-config interface {iface}")
        ip_match = re.search(r"ipv4 address\s+(\d+\.\d+\.\d+\.\d+)", iface_output)
        if ip_match:
            interfaces[iface]["ip"] = ip_match.group(1)
        desc_match = re.search(r'description\s+"([^"]+)"', iface_output)
        if desc_match:
            interfaces[iface]["description"] = desc_match.group(1)
            peer_match = re.search(r"trunk to\s+(\S+)", desc_match.group(1))
            if peer_match:
                interfaces[iface]["peer"] = peer_match.group(1).rstrip(",")
    return interfaces


def run_arcos_capture(args, net_connect):
    """ArcOS: enter bash, sudo, tcpdump, base64 transfer."""
    if not args.interface:
        args.interface = "any"
    if not args.output:
        args.output = f"isis-{args.device}.pcap" if args.isis_interface else f"{args.device}.pcap"

    remote_dir = args.remote_dir or "/tmp"
    remote_pcap = f"{remote_dir}/{args.output}"
    local_pcap = os.path.join(args.local_dir, args.output)
    tcpdump_cmd = build_tcpdump_cmd(args, remote_pcap)

    print(f"[*] Command:   {tcpdump_cmd}")
    print(f"[*] Output:    {local_pcap}")
    print()

    # Get the underlying paramiko channel for interactive work
    channel = net_connect.remote_conn
    prompt_pat = r"(#|\\$)\s*$"

    # Enter bash
    print("[2/5] Entering root shell ...")
    send_and_wait(channel, "bash", [r"\$\s*$"], timeout=10)
    send_and_wait(channel, "sudo -i", [r"[Pp]assword|root@"], timeout=10)
    # Check if password was requested
    output, _ = read_until(channel, [r"root@|#\s*$"], timeout=2)
    if "assword" in output.lower():
        send_and_wait(channel, args.password, [r"root@|#"], timeout=10)
    time.sleep(0.5)

    # Verify root
    output, _ = send_and_wait(channel, "id", [r"#"], timeout=5)
    if "uid=0" not in output:
        print("[!] Failed to get root shell")
        sys.exit(1)

    # Start tcpdump
    print(f"[3/5] Starting tcpdump ({args.duration}s) ...")
    channel.send(tcpdump_cmd + "\n")
    output, idx = read_until(channel, [r"listening on", r"tcpdump:"], timeout=15)
    if idx < 0:
        print("[!] tcpdump failed to start")
        print(output)
        sys.exit(1)
    print("[*] Capturing ...")

    if args.duration > 0:
        for remaining in range(args.duration, 0, -10):
            print(f"     {remaining}s remaining ...", end="\r")
            time.sleep(min(10, remaining))
        print("     Capture complete.           ")
        channel.send("\x03")  # Ctrl+C
    else:
        read_until(channel, [r"packets captured", r"#"], timeout=3600)

    read_until(channel, [r"#"], timeout=10)
    time.sleep(0.5)

    # Verify file
    output, _ = send_and_wait(channel, f"ls -la {remote_pcap}", [r"#"], timeout=5)
    if "No such file" in output:
        print("[!] Remote pcap not found.")
        sys.exit(1)
    for line in output.split("\n"):
        if args.output in line:
            print(f"[*] Remote: {line.strip()}")

    # Transfer via base64
    print("[4/5] Transferring pcap via base64 ...")
    marker = "===BASE64END==="
    channel.send(f"base64 -w0 {remote_pcap} && echo {marker}\n")
    output, idx = read_until(channel, [marker], timeout=300)
    if idx < 0:
        print("[!] base64 transfer timed out")
        sys.exit(1)
    read_until(channel, [r"#"], timeout=5)

    # Extract base64 data
    cleaned = re.sub(r"\x1b\[[^a-zA-Z]*[a-zA-Z]", "", output)
    # Remove the command echo and everything before the actual data
    lines = cleaned.split("\n")
    b64_lines = [l for l in lines if re.match(r"^[A-Za-z0-9+/=]+$", l.strip())]
    b64_data = "".join(l.strip() for l in b64_lines)
    if not b64_data:
        # Fallback: grab all base64 chars
        b64_data = re.sub(r"[^A-Za-z0-9+/=]", "", cleaned)
    b64_data = b64_data.rstrip("=")
    b64_data += "=" * (-len(b64_data) % 4)

    pcap_bytes = base64.b64decode(b64_data)
    with open(local_pcap, "wb") as f:
        f.write(pcap_bytes)

    # Cleanup
    if not args.keep_remote:
        send_and_wait(channel, f"rm -f {remote_pcap}", [r"#"], timeout=5)
        print("[*] Remote file deleted.")

    # Exit
    print("[5/5] Exiting ...")
    channel.send("exit\n")
    time.sleep(0.3)
    channel.send("exit\n")
    time.sleep(0.3)

    return local_pcap


# ============================================================
# Juniper functions
# ============================================================

def discover_loopback_ip_junos(net_connect):
    output = net_connect.send_command("show interfaces lo0.0 | match \"Local:\"")
    match = re.search(r"Local:\s+(\d+\.\d+\.\d+\.\d+)", output)
    if match:
        return match.group(1)
    output = net_connect.send_command("show configuration interfaces lo0 unit 0 family inet | display set")
    match = re.search(r"address\s+(\d+\.\d+\.\d+\.\d+)", output)
    return match.group(1) if match else None


def discover_isis_interfaces_junos(net_connect):
    isis_output = net_connect.send_command("show isis interface")
    interfaces = {}
    for line in isis_output.split("\n"):
        line = line.strip()
        if not line or "Interface" in line or line.startswith("-") or line.startswith("IS-IS"):
            continue
        parts = line.split()
        if not parts:
            continue
        iface_name = parts[0]
        if iface_name.startswith("lo"):
            continue
        if re.match(r"(ae|ge-|xe-|et-|irb\.|swp|bond)", iface_name):
            interfaces[iface_name] = {"ip": None, "description": "", "peer": ""}

    for iface in list(interfaces.keys()):
        iface_output = net_connect.send_command(f"show interfaces {iface} terse | match inet")
        ip_match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", iface_output)
        if ip_match:
            interfaces[iface]["ip"] = ip_match.group(1)
        desc_output = net_connect.send_command(f"show interfaces {iface} | match Description")
        desc_match = re.search(r"Description:\s+(.+)", desc_output)
        if desc_match:
            interfaces[iface]["description"] = desc_match.group(1).strip()
            peer_match = re.search(r"(?:to|TO)\s+(\S+)", desc_match.group(1))
            if peer_match:
                interfaces[iface]["peer"] = peer_match.group(1).rstrip(",")
    return interfaces


def run_juniper_capture(args, net_connect):
    """Juniper: monitor traffic, then shell + base64 transfer."""
    if not args.interface:
        args.interface = "lo0.0"
    if not args.output:
        if args.isis_interface:
            iface_short = args.isis_interface.split(".")[0]
            args.output = f"{args.device}-{iface_short}.pcap"
        else:
            args.output = f"{args.device}.pcap"

    remote_dir = args.remote_dir or "/var/tmp"
    remote_filename = args.output
    remote_pcap = f"{remote_dir}/{remote_filename}"
    local_pcap = os.path.join(args.local_dir, args.output)
    monitor_cmd = build_monitor_traffic_cmd(args, remote_pcap)

    print(f"[*] Command:   {monitor_cmd}")
    print(f"[*] Output:    {local_pcap}")
    print()

    # Use paramiko channel for the interactive capture
    channel = net_connect.remote_conn

    # Juniper prompt pattern
    junos_prompt = r"\S+@\S+>"

    # Start monitor traffic
    print(f"[2/4] Starting monitor traffic ({args.duration}s) ...")
    channel.send(monitor_cmd + "\n")
    output, idx = read_until(channel, [r"Listening on", r"Address resolution"], timeout=15)
    if idx < 0:
        print("[!] monitor traffic failed to start")
        print(output)
        sys.exit(1)
    print("[*] Capturing ...")

    if args.duration > 0:
        for remaining in range(args.duration, 0, -10):
            print(f"     {remaining}s remaining ...", end="\r")
            time.sleep(min(10, remaining))
        print("     Capture complete.           ")
        channel.send("\x03")  # Ctrl+C
    else:
        read_until(channel, [r"packets received", junos_prompt], timeout=3600)

    # Wait for the prompt to return after Ctrl+C
    time.sleep(2)
    # Drain any remaining output
    while channel.recv_ready():
        channel.recv(65535)
        time.sleep(0.3)
    # Send empty line to get a clean prompt
    channel.send("\n")
    read_until(channel, [junos_prompt], timeout=10)
    time.sleep(0.5)

    # Verify file exists — try multiple locations
    candidates = [
        remote_pcap,                              # /var/tmp/device.pcap
        remote_pcap.replace(".pcap", ""),          # /var/tmp/device (no ext)
        f"/var/tmp/{remote_filename}",            # explicit /var/tmp/
    ]
    found_pcap = None
    for candidate in candidates:
        output, _ = send_and_wait(channel, f"file list {candidate}", [junos_prompt], timeout=10)
        if "No such file" not in output and "not found" not in output and candidate.split("/")[-1] in output:
            found_pcap = candidate
            break
    if not found_pcap:
        # Last resort: list /var/tmp/ and look for our file
        output, _ = send_and_wait(channel, f"file list /var/tmp/{args.device}*", [junos_prompt], timeout=10)
        print(f"[!] Remote pcap not found — capture may have failed.")
        print(f"    Searched: {candidates}")
        print(f"    /var/tmp listing: {output.strip()}")
        sys.exit(1)
    remote_pcap = found_pcap
    print(f"[*] Remote file: {remote_pcap}")

    # Enter shell for base64 transfer
    print("[3/4] Transferring pcap via base64 ...")
    channel.send("start shell\n")
    read_until(channel, [r"(%|\$)\s*$"], timeout=10)
    time.sleep(0.5)

    marker = "===BASE64END==="
    channel.send(f"base64 -w0 {remote_pcap} && echo {marker}\n")
    output, idx = read_until(channel, [marker], timeout=300)
    if idx < 0:
        print("[!] base64 transfer timed out")
        sys.exit(1)
    read_until(channel, [r"(%|\$)"], timeout=5)

    # Extract base64 data
    cleaned = re.sub(r"\x1b\[[^a-zA-Z]*[a-zA-Z]", "", output)
    lines = cleaned.split("\n")
    b64_lines = [l for l in lines if re.match(r"^[A-Za-z0-9+/=]+$", l.strip())]
    b64_data = "".join(l.strip() for l in b64_lines)
    if not b64_data:
        b64_data = re.sub(r"[^A-Za-z0-9+/=]", "", cleaned)
    b64_data = b64_data.rstrip("=")
    b64_data += "=" * (-len(b64_data) % 4)

    pcap_bytes = base64.b64decode(b64_data)
    with open(local_pcap, "wb") as f:
        f.write(pcap_bytes)

    # Cleanup
    if not args.keep_remote:
        send_and_wait(channel, f"rm -f {remote_pcap}", [r"(%|\$)"], timeout=5)
        print("[*] Remote file deleted.")

    # Exit
    print("[4/4] Exiting ...")
    channel.send("exit\n")
    time.sleep(0.3)

    return local_pcap



# ============================================================
# Arista functions
# ============================================================

def discover_loopback_ip_arista(net_connect):
    output = net_connect.send_command("show ip interface Loopback0 | json")
    # JSON output from eAPI
    import json
    try:
        data = json.loads(output)
        addrs = data.get("interfaces", {}).get("Loopback0", {}).get("interfaceAddress", [])
        if addrs:
            return addrs[0].get("primaryIp", {}).get("address")
    except (json.JSONDecodeError, KeyError, IndexError):
        pass
    # Fallback: text parsing
    output = net_connect.send_command("show ip interface Loopback0")
    match = re.search(r"Internet address is\s+(\d+\.\d+\.\d+\.\d+)", output)
    return match.group(1) if match else None


def discover_ospf_interfaces_arista(net_connect):
    """Discover OSPF interfaces on Arista EOS."""
    output = net_connect.send_command("show ip ospf interface brief")
    interfaces = {}
    for line in output.split("\n"):
        line = line.strip()
        if not line or "Interface" in line or line.startswith("-"):
            continue
        parts = line.split()
        if not parts:
            continue
        iface_name = parts[0]
        if iface_name.startswith(("Lo", "lo")):
            continue
        if re.match(r"(Et|Ethernet|Po|Port-Channel|Vlan|Ma|Management)", iface_name):
            # EOS columns: Interface Instance VRF Area IP/mask Cost State Nbrs
            # Skip 0.0.0.0 (area) — look for IP with /prefix
            ip = None
            for p in parts[1:]:
                m = re.match(r"(\d+\.\d+\.\d+\.\d+)/\d+", p)
                if m:
                    ip = m.group(1)
                    break
            interfaces[iface_name] = {"ip": ip, "description": "", "peer": ""}

    # Get descriptions
    for iface in list(interfaces.keys()):
        desc_output = net_connect.send_command(f"show interfaces {iface} | include Description")
        desc_match = re.search(r"Description:\s+(.+)", desc_output)
        if desc_match:
            interfaces[iface]["description"] = desc_match.group(1).strip()
            peer_match = re.search(r"(?:to|TO)\s+(\S+)", desc_match.group(1))
            if peer_match:
                interfaces[iface]["peer"] = peer_match.group(1).rstrip(",")
    return interfaces


def eos_to_linux_iface(name):
    """Map EOS interface name to Linux interface name for tcpdump in bash.
    Et33/1 -> et33_1, Ethernet33/1 -> et33_1, Port-Channel1 -> po1
    """
    if not name or name == "any":
        return name
    # Ethernet / Et -> et
    m = re.match(r"(?:Ethernet|Et)(\d+(?:/\d+)*)", name)
    if m:
        return "et" + m.group(1).replace("/", "_")
    # Port-Channel / Po -> po
    m = re.match(r"(?:Port-Channel|Po)(\d+)", name)
    if m:
        return "po" + m.group(1)
    # Management / Ma -> ma
    m = re.match(r"(?:Management|Ma)(\d+)", name)
    if m:
        return "ma" + m.group(1)
    # Vlan -> vlan
    m = re.match(r"Vlan(\d+)", name)
    if m:
        return "vlan" + m.group(1)
    return name


def run_arista_capture(args, net_connect):
    """Arista EOS: enable -> bash -> sudo tcpdump -> base64 transfer."""
    if not args.interface:
        args.interface = "any"
    if not args.output:
        args.output = f"ospf-{args.device}.pcap" if args.ospf_interface else f"{args.device}.pcap"

    # Sanitize filename — interface names like Et33/1 contain /
    args.output = args.output.replace("/", "_")
    # Map EOS interface name to Linux name for bash tcpdump
    linux_iface = eos_to_linux_iface(args.interface)
    if linux_iface != args.interface:
        print(f"[*] Interface mapping: {args.interface} -> {linux_iface}")
    args.interface = linux_iface
    remote_dir = args.remote_dir or "/tmp"
    remote_pcap = f"{remote_dir}/{args.output}"
    local_pcap = os.path.join(args.local_dir, args.output)
    tcpdump_cmd = build_tcpdump_cmd_arista(args, remote_pcap)

    print(f"[*] Command:   {tcpdump_cmd}")
    print(f"[*] Output:    {local_pcap}")
    print()

    # Get paramiko channel for interactive work
    channel = net_connect.remote_conn

    # Enter bash from EOS CLI
    print("[2/5] Entering bash shell ...")
    channel.send("bash\n")
    output, idx = read_until(channel, [r"\$\s*$", r"bash-"], timeout=10)
    if idx < 0:
        # Try sending newline
        channel.send("\n")
        output, idx = read_until(channel, [r"\$\s*$", r"bash-"], timeout=5)
    time.sleep(0.5)

    # Start tcpdump (Arista bash runs as root already in most cases)
    print(f"[3/5] Starting tcpdump ({args.duration}s) ...")
    channel.send(tcpdump_cmd + "\n")
    output, idx = read_until(channel, [r"listening on", r"No such device|Permission denied|tcpdump:\s+\S+:"], timeout=15)
    if idx == 1:
        print(f"[!] tcpdump error: {output.strip()}")
        sys.exit(1)
    if idx < 0:
        print("[!] tcpdump failed to start")
        print(output)
        sys.exit(1)
    print("[*] Capturing ...")

    if args.duration > 0:
        for remaining in range(args.duration, 0, -10):
            print(f"     {remaining}s remaining ...", end="\r")
            time.sleep(min(10, remaining))
        print("     Capture complete.           ")
        channel.send("\x03")  # Ctrl+C
    else:
        read_until(channel, [r"packets captured", r"\$"], timeout=3600)

    read_until(channel, [r"\$"], timeout=10)
    time.sleep(0.5)

    # Verify file (tcpdump with -C/-W may add numeric suffix)
    output, _ = send_and_wait(channel, f"ls -la {remote_pcap}*", [r"\$"], timeout=5)
    if "No such file" in output or remote_pcap.split("/")[-1] not in output:
        # Debug: list /tmp to see what tcpdump created
        debug_out, _ = send_and_wait(channel, f"ls -la {remote_dir}/{args.device}* 2>/dev/null; ls -la {remote_dir}/*.pcap* 2>/dev/null", [r"\$"], timeout=5)
        print(f"[!] Remote pcap not found at {remote_pcap}")
        print(f"[!] Files in {remote_dir}: {debug_out.strip()}")
        sys.exit(1)
    # If -C/-W created a suffixed file, update remote_pcap
    for line in output.split("\n"):
        if remote_pcap.split("/")[-1] in line:
            parts = line.split()
            if parts:
                actual_file = parts[-1]
                if actual_file != remote_pcap and actual_file.startswith(remote_pcap):
                    remote_pcap = actual_file
            print(f"[*] Remote: {line.strip()}")

    # Transfer via base64
    print("[4/5] Transferring pcap via base64 ...")
    marker_start = "===BASE64START==="
    marker_end = "===BASE64END==="
    channel.send(f"echo {marker_start} && base64 -w0 {remote_pcap} && echo && echo {marker_end}\n")
    output, idx = read_until(channel, [marker_end], timeout=300)
    if idx < 0:
        print("[!] base64 transfer timed out")
        sys.exit(1)
    read_until(channel, [r"\$"], timeout=5)

    # Extract base64 data between markers
    cleaned = re.sub(r"\x1b\[[^a-zA-Z]*[a-zA-Z]", "", output)
    # Find data between start and end markers
    m = re.search(marker_start + r"\s*\n(.+?)\s*" + marker_end, cleaned, re.DOTALL)
    if m:
        b64_raw = m.group(1).strip()
        # Remove any non-base64 characters (newlines, prompts)
        b64_data = re.sub(r"[^A-Za-z0-9+/=]", "", b64_raw)
    else:
        # Fallback: look for lines that are pure base64
        lines = cleaned.split("\n")
        b64_lines = [l for l in lines if re.match(r"^[A-Za-z0-9+/=]{4,}$", l.strip())]
        b64_data = "".join(l.strip() for l in b64_lines)
    if not b64_data:
        print("[!] No base64 data captured (pcap may be empty)")
        print(f"[!] Debug output: {cleaned[:500]}")
        sys.exit(1)
    # Fix padding
    pad = len(b64_data) % 4
    if pad:
        b64_data += "=" * (4 - pad)

    pcap_bytes = base64.b64decode(b64_data)
    with open(local_pcap, "wb") as f:
        f.write(pcap_bytes)

    # Cleanup
    if not args.keep_remote:
        send_and_wait(channel, f"rm -f {remote_pcap}", [r"\$"], timeout=5)
        print("[*] Remote file deleted.")

    # Exit bash back to EOS
    print("[5/5] Exiting ...")
    channel.send("exit\n")
    time.sleep(0.3)

    return local_pcap


def build_tcpdump_cmd_arista(args, remote_pcap):
    """Build tcpdump command for Arista EOS bash."""
    if getattr(args, "ospf_capture", False):
        loopback = getattr(args, "loopback_ip", None)
        if loopback:
            bpf = f"'proto ospf or (ip host {loopback})'"
        else:
            bpf = "'proto ospf'"
        parts = ["sudo", "tcpdump", "-eni", args.interface, bpf]
    else:
        parts = ["sudo", "tcpdump", "-eni", args.interface]
        filters = []
        if args.host_filter:
            filters.append(f"host {args.host_filter}")
        if args.port:
            filters.append(f"port {args.port}")
        if args.exclude_port:
            filters.append(f"not port {args.exclude_port}")
        if args.protocol:
            filters.append(args.protocol)
        if filters:
            parts.append("'" + " and ".join(filters) + "'")
    parts.extend(["-w", remote_pcap, "-C", str(args.max_size), "-W", "1"])
    if args.snap_len > 0:
        parts.extend(["-s", str(args.snap_len)])
    if args.packet_count > 0:
        parts.extend(["-c", str(args.packet_count)])
    return " ".join(parts)


# ============================================================
# Nokia SROS functions
# ============================================================

class NokiaSROSCapture:
    """Nokia SROS packet capture using mirror/pcap functionality.
    Uses paramiko directly for reliable SSH handling.
    """

    def __init__(self, hostname, username, password):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.ssh_client = None
        self.channel = None
        self.system_ip = None
        self.pcap_user = "ftppcap"
        self.pcap_pass = "Nokia123"  # Simple alphanumeric password
        self.pcap_dir = "cf3:/pcap"
        self.pcap_session = "pcap98"  # PCAP session name for debug commands
        self.mirror_id = "98"  # Use high ID to avoid conflicts

    def connect(self):
        """Connect to Nokia SROS using pexpect (native SSH).

        Uses pexpect for more reliable SSH to Nokia SROS.
        Handles passwords with special characters by writing to temp file.
        """
        import tempfile
        import os as _os

        # SSH options - disable pubkey auth, force password auth, ignore config files
        # Use -F /dev/null to avoid system ssh_config overriding our options
        ssh_opts = "-F /dev/null -tt -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1"

        # Debug: verify password is set
        if not self.password:
            raise Exception("Password is empty - check DEVICE_PASSWORD environment variable")

        # Write password to temp file to avoid shell expansion issues with special chars
        self._pw_file = tempfile.NamedTemporaryFile(mode='w', delete=False, prefix='.sshpw_')
        self._pw_file.write(self.password)
        self._pw_file.close()

        # Use expect directly (not sshpass) to avoid password mangling
        cmd = f'SSH_AUTH_SOCK= ssh {ssh_opts} {self.username}@{self.hostname}'
        self.child = pexpect.spawn('/bin/bash', ['-c', cmd], encoding='utf-8', timeout=60)
        self.child.setwinsize(50, 200)

        # Wait for password prompt
        prompt_pattern = r'[*A]:[^\s]+[#>]'
        try:
            idx = self.child.expect(['[Pp]assword:', pexpect.TIMEOUT, pexpect.EOF], timeout=30)
            if idx == 0:
                # Read password from file and send it (avoids shell expansion issues)
                with open(self._pw_file.name, 'r') as f:
                    pw = f.read()
                self.child.sendline(pw)
                # Wait for prompt
                idx = self.child.expect([prompt_pattern, 'Permission denied', 'Too many authentication', pexpect.TIMEOUT, pexpect.EOF], timeout=15)
                if idx == 1:
                    raise Exception("SSH authentication failed - check username/password")
                elif idx == 2:
                    raise Exception("SSH rate limited. Wait and try again.")
                elif idx == 3 or idx == 4:
                    output = self.child.before if self.child.before else ""
                    if re.search(prompt_pattern, output):
                        pass  # Got prompt in buffer, we're connected
                    else:
                        raise Exception(f"SSH connection timeout: {output[:200]}")
            elif idx == 1:
                # Timeout waiting for password prompt
                output = self.child.before if self.child.before else ""
                raise Exception(f"SSH timeout waiting for password prompt: {output[:200]}")
            elif idx == 2:
                output = self.child.before if self.child.before else ""
                raise Exception(f"SSH connection closed: {output[:200]}")
        finally:
            # Clean up password file
            try:
                _os.unlink(self._pw_file.name)
            except Exception:
                pass

        # Send a newline to get a fresh prompt
        self.child.sendline('')
        time.sleep(0.5)

        # Verify we have a working connection
        try:
            self.child.expect([prompt_pattern, pexpect.TIMEOUT], timeout=3)
        except pexpect.TIMEOUT:
            pass  # May timeout if buffer empty, but connection might still be OK
        except pexpect.EOF:
            raise Exception("SSH connection closed unexpectedly")

    def disconnect(self):
        """Close connection."""
        try:
            if hasattr(self, 'child') and self.child:
                self.child.sendline('exit')
                self.child.close()
        except Exception:
            pass

    def _read_until_prompt(self, timeout=30):
        """Read output until prompt is detected."""
        try:
            # Nokia prompts end with # or >
            self.child.expect([r'[#>]\s*$'], timeout=timeout)
            return self.child.before + self.child.after
        except pexpect.TIMEOUT:
            return self.child.before if self.child.before else ""
        except pexpect.EOF:
            return self.child.before if self.child.before else ""

    def _send_and_wait(self, command, timeout=30):
        """Send a command and wait for prompt."""
        self.child.sendline(command)
        time.sleep(0.3)
        return self._read_until_prompt(timeout)

    def send_command(self, command, print_output=False):
        """Send operational command."""
        output = self._send_and_wait(command)
        if print_output:
            print(f"    {command}")
            for line in output.strip().split('\n')[:10]:
                print(f"      {line}")
        return output

    def send_config(self, commands, commit=True, debug=False):
        """Send configuration commands.

        Detects CLI mode and uses appropriate syntax.
        For classic CLI: Uses 'configure' and classic command format
        For MD-CLI: Uses 'configure private' and MD-CLI format
        """
        cli_mode = getattr(self, 'cli_mode', 'classic')

        if cli_mode == "md-cli":
            # MD-CLI mode
            output = self._send_and_wait("configure private", timeout=10)
            if debug:
                print(f"    [DEBUG] After 'configure private': ...{output.strip()[-80:]}")

            for cmd in commands:
                if cmd.startswith("/configure "):
                    cmd = cmd[11:]
                if debug:
                    print(f"    [DEBUG] Sending: {cmd[:60]}...")
                output = self._send_and_wait(cmd, timeout=10)
                if debug:
                    print(f"    [DEBUG] Response: ...{output.strip()[-100:]}")
                if "MINOR:" in output or "MAJOR:" in output:
                    for line in output.split('\n'):
                        if "MINOR:" in line or "MAJOR:" in line:
                            print(f"    [!] {line.strip()}")
                self._send_and_wait("/configure", timeout=5)

            if commit:
                output = self._send_and_wait("commit", timeout=30)
                if "MINOR:" in output or "MAJOR:" in output:
                    for line in output.split('\n'):
                        if "MINOR:" in line or "MAJOR:" in line:
                            print(f"    [!] {line.strip()}")

            self.child.sendline("exit all")
            time.sleep(0.5)
            try:
                idx = self.child.expect([r'Discard.*\[y,n\]', r'[#>]\s*$'], timeout=5)
                if idx == 0:
                    self.child.sendline("y")
                    self._read_until_prompt(timeout=5)
            except Exception:
                pass
        else:
            # Classic CLI mode
            output = self._send_and_wait("configure", timeout=10)
            if debug:
                print(f"    [DEBUG] After 'configure': ...{output.strip()[-80:]}")

            for cmd in commands:
                # Convert MD-CLI style commands to classic CLI if needed
                # "delete X" -> "no X"
                if cmd.startswith("delete "):
                    cmd = "no " + cmd[7:]
                if debug:
                    print(f"    [DEBUG] Sending: {cmd[:60]}...")
                output = self._send_and_wait(cmd, timeout=10)
                if debug:
                    print(f"    [DEBUG] Response: ...{output.strip()[-100:]}")
                # Skip error checking for 'exit' commands
                if cmd.strip() != "exit":
                    if "Error:" in output or "MINOR:" in output or "MAJOR:" in output:
                        for line in output.split('\n'):
                            if "Error:" in line or "MINOR:" in line or "MAJOR:" in line:
                                print(f"    [!] {line.strip()}")

            # Exit config mode completely
            self._send_and_wait("exit all", timeout=5)

    def detect_cli_mode(self):
        """Detect if device is running MD-CLI or classic CLI."""
        # Send a test command and check response
        output = self._send_and_wait("environment more false", timeout=5)
        # Check prompt format: MD-CLI uses [/] or [pr:/configure], classic uses >
        # Also check for specific command responses
        if ">config" in output or "A:admin@" in output or "*A:" in output:
            self.cli_mode = "classic"
        else:
            self.cli_mode = "md-cli"
        return self.cli_mode

    def discover_system_ip(self):
        """Discover system (loopback) IP address."""
        output = self.send_command("show router interface system")
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)/32", output)
        if match:
            self.system_ip = match.group(1)
            return self.system_ip
        # Also try without /32
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)", output)
        if match:
            self.system_ip = match.group(1)
        return self.system_ip

    def discover_management_ip(self):
        """Discover management IP address (for FTP server access).

        The FTP server is typically accessible via the management interface,
        not the system (loopback) interface in the base router.
        """
        # First try show system information which shows management IP directly
        output = self.send_command("show system information")
        match = re.search(r"Management IPv4 Addr\s*:\s*(\d+\.\d+\.\d+\.\d+)", output)
        if match:
            self.management_ip = match.group(1)
            return self.management_ip

        # Fallback: try management router interface
        output = self.send_command("show router management interface")
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)/\d+", output)
        if match:
            self.management_ip = match.group(1)
            return self.management_ip

        # Last resort: use system IP
        return self.discover_system_ip()

    def discover_isis_interfaces(self):
        """Discover ISIS interfaces and their details."""
        interfaces = {}
        output = self.send_command("show router isis adjacency")

        # Parse adjacency output for interface names
        for line in output.split("\n"):
            # Look for interface patterns like 1/1/c1/1 or lag-1
            match = re.search(r"(\d+/\d+/c?\d+(?:/\d+)?|lag-\d+)", line)
            if match:
                iface = match.group(1)
                if iface not in interfaces:
                    interfaces[iface] = {"ip": None, "description": "", "peer": ""}
                    # Try to get peer from same line
                    parts = line.split()
                    if len(parts) >= 2:
                        interfaces[iface]["peer"] = parts[0]  # System ID or name

        # If no adjacencies, try to get from ISIS config
        if not interfaces:
            output = self.send_command("show router isis interface")
            for line in output.split("\n"):
                match = re.search(r"(\d+/\d+/c?\d+(?:/\d+)?|lag-\d+)", line)
                if match:
                    iface = match.group(1)
                    interfaces[iface] = {"ip": None, "description": "", "peer": ""}

        # Get descriptions for interfaces
        for iface in list(interfaces.keys()):
            output = self.send_command(f"show port {iface}")
            desc_match = re.search(r"Description\s*:\s*(.+)", output)
            if desc_match:
                interfaces[iface]["description"] = desc_match.group(1).strip()
                peer_match = re.search(r"(?:to|TO)\s+(\S+)", desc_match.group(1))
                if peer_match:
                    interfaces[iface]["peer"] = peer_match.group(1).rstrip(",")

        return interfaces

    def discover_ports(self):
        """Discover all ports on the device."""
        ports = {}
        output = self.send_command("show port")
        for line in output.split("\n"):
            # Match port patterns like 1/1/c1/1 (must have /1 at end for actual port)
            # Skip connectors like 1/1/c1 (no trailing /number)
            match = re.match(r"\s*(\d+/\d+/c\d+/\d+)\s+", line)
            if match:
                port = match.group(1)
                ports[port] = {"description": "", "state": ""}
                # Extract state (Up/Down)
                if "Up" in line:
                    ports[port]["state"] = "Up"
                elif "Down" in line:
                    ports[port]["state"] = "Down"
        return ports

    def cleanup_existing_mirror(self, pcap_filename=None):
        """Clean up any existing mirror configuration and pcap files before setting up new capture."""
        cli_mode = getattr(self, 'cli_mode', 'classic')

        print("    [*] Cleaning up existing configuration...")

        # Stop any running capture first
        if cli_mode == "classic":
            self._send_and_wait(f'debug pcap {self.pcap_session} capture stop', timeout=5)
            # Remove debug mirror-source
            self._send_and_wait(f'debug mirror-source {self.mirror_id} shutdown', timeout=5)
            self._send_and_wait(f'no debug mirror-source {self.mirror_id}', timeout=5)
        else:
            self._send_and_wait(f'debug mirror-dest {self.mirror_id} pcap capture-stop', timeout=5)
        time.sleep(1)

        # Delete pcap file if it exists (must do before reconfiguring file-url)
        if pcap_filename:
            self.send_command(f"file del {self.pcap_dir}/{pcap_filename} force")
        # Also delete any existing pcap files in the directory
        self.send_command(f"file del {self.pcap_dir}/*.pcap force")
        time.sleep(0.5)

        # Check if mirror config exists
        output = self.send_command(f"show mirror mirror-dest {self.mirror_id}")
        if "not found" in output.lower() or "does not exist" in output.lower() or "No Matching" in output:
            return  # No existing config

        # Delete mirror config
        if cli_mode == "classic":
            self.send_config([
                f"no mirror mirror-dest {self.mirror_id}",
            ])
        else:
            self.send_config([
                f"delete mirror mirror-source {self.mirror_id}",
                f"delete mirror mirror-dest {self.mirror_id}",
            ])
        time.sleep(1)

    def ensure_mixed_mode(self):
        """Ensure device is in mixed configuration mode for classic CLI debug commands."""
        output = self.send_command('admin show configuration /configure system management-interface configuration-mode')
        if 'model-driven' in output and 'mixed' not in output:
            print("    [*] Enabling mixed configuration mode for classic CLI commands...")
            self.send_config([
                'system management-interface configuration-mode mixed',
            ])
            time.sleep(1)

    def _get_local_ip_for_device(self):
        """Get the local IP address that the Nokia device can reach."""
        # Try to connect to the device and see what local IP we use
        import socket
        try:
            # Try to resolve device hostname
            device_ip = socket.gethostbyname(self.hostname)
            # Create a UDP socket (doesn't actually send anything)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((device_ip, 22))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return None

    def _start_ftp_server(self, pcap_dir, username="pcap", password="pcap123"):
        """Start a simple FTP server to receive pcap files."""
        import threading
        try:
            from pyftpdlib.handlers import FTPHandler
            from pyftpdlib.servers import FTPServer
            from pyftpdlib.authorizers import DummyAuthorizer
        except ImportError:
            print("    [!] pyftpdlib not installed. Install with: pip install pyftpdlib")
            return None, None

        # Create directory if needed
        os.makedirs(pcap_dir, exist_ok=True)

        # Set up authorizer with write permissions
        authorizer = DummyAuthorizer()
        authorizer.add_user(username, password, pcap_dir, perm="elradfmw")

        # FTP handler
        handler = FTPHandler
        handler.authorizer = authorizer
        handler.passive_ports = range(60000, 60100)

        # Find an available port
        ftp_port = 2121
        for port in range(2121, 2200):
            try:
                server = FTPServer(("0.0.0.0", port), handler)
                ftp_port = port
                break
            except OSError:
                continue
        else:
            print("    [!] Could not find available port for FTP server")
            return None, None

        # Start server in a thread
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()

        self.ftp_server = server
        self.ftp_port = ftp_port
        self.ftp_user = username
        self.ftp_pass = password
        self.ftp_dir = pcap_dir

        return server, ftp_port

    def _stop_ftp_server(self):
        """Stop the FTP server."""
        if hasattr(self, 'ftp_server') and self.ftp_server:
            try:
                self.ftp_server.close_all()
            except Exception:
                pass

    def _setup_local_ftp_server(self):
        """Configure the Nokia device to act as its own FTP server for pcap storage.

        Nokia SROS pcap requires FTP URL format, but we can use the device's own
        FTP server - the device acts as both FTP client and server simultaneously.
        This allows pcap files to be stored locally on cf3: via FTP to itself.
        """
        print("    [*] Configuring device as local FTP server...")
        cli_mode = getattr(self, 'cli_mode', 'classic')

        # Create pcap directory first (command-level, not config mode)
        self.send_command(f"file md {self.pcap_dir}")

        if cli_mode == "classic":
            # Classic CLI: use single-line configure commands
            # These commands are idempotent - they update existing config if present

            # Enable FTP server (already enabled on most devices, but ensure it)
            self._send_and_wait("configure system security ftp-server", timeout=10)
            self._send_and_wait("exit all", timeout=5)

            # Configure user - check if user exists first
            output = self.send_command(f"show system security user {self.pcap_user}")
            if "Number of users : 0" in output or "No matching entries" in output:
                # User doesn't exist, create it
                self._send_and_wait(f'configure system security user {self.pcap_user} create', timeout=10)
                self._send_and_wait(f'password {self.pcap_pass}', timeout=10)
                self._send_and_wait('access ftp', timeout=10)
                self._send_and_wait(f'home-directory {self.pcap_dir}', timeout=10)
                self._send_and_wait("exit all", timeout=5)
            else:
                # User exists, just ensure home-directory is set
                self._send_and_wait(f'configure system security user {self.pcap_user} home-directory {self.pcap_dir}', timeout=10)
                self._send_and_wait("exit all", timeout=5)
        else:
            # MD-CLI mode
            self.send_config([
                f"system security ftp-server",
                f'system security user "{self.pcap_user}" password "{self.pcap_pass}"',
                f'system security user "{self.pcap_user}" access ftp true',
                f'system security user "{self.pcap_user}" console home-directory "{self.pcap_dir}"',
            ])

        print(f"    [*] FTP server enabled, user '{self.pcap_user}' configured")

    def setup_capture(self, interface, pcap_filename, local_pcap_dir=".", ftp_url=None):
        """Configure mirror for pcap capture using device's local FTP server.

        Nokia SROS pcap requires FTP URL format. We configure the device to act as
        its own FTP server - the pcap is written via FTP to the device itself,
        storing the file locally on cf3:. This is Nokia's recommended approach.

        Args:
            interface: Port to capture on (e.g., "1/1/c1/1")
            pcap_filename: Name of the pcap file
            local_pcap_dir: Local directory to save downloaded file
            ftp_url: Optional external FTP URL (if not provided, uses device's own FTP)
        """
        cli_mode = getattr(self, 'cli_mode', 'classic')
        print(f"    [*] CLI mode: {cli_mode}")

        # Clean up any leftover mirror config from previous runs
        self.cleanup_existing_mirror(pcap_filename)

        # Determine file URL to use
        if ftp_url:
            file_url = ftp_url
            print(f"    [*] Using provided external FTP URL")
        else:
            # Configure device as its own FTP server (Nokia recommended approach)
            self._setup_local_ftp_server()

            # Get management IP for FTP URL (FTP server is on management interface)
            mgmt_ip = getattr(self, 'management_ip', None) or self.discover_management_ip()
            if not mgmt_ip:
                print("    [!] Could not determine management IP for local FTP")
                return False

            # Build FTP URL using device's management IP as server
            # FTP server listens on management interface, not system loopback
            file_url = f"ftp://{self.pcap_user}:{self.pcap_pass}@{mgmt_ip}/{pcap_filename}"
            print(f"    [*] Using device's local FTP server at {mgmt_ip}")

        self.pcap_remote_file = f"{self.pcap_dir}/{pcap_filename}"
        self.pcap_use_ftp = True  # Always using FTP (either external or local)

        print("[2/6] Configuring mirror destination ...")

        if cli_mode == "classic":
            # Classic CLI: mirror-dest must be shutdown before configuring file-url
            self.send_config([
                f"mirror mirror-dest {self.mirror_id} create",
                "shutdown",
                f"pcap {self.pcap_session} create",
                f'file-url "{file_url}"',
                "exit",  # Exit pcap context
                "exit",  # Exit mirror-dest context
            ], debug=True)

            # Enable mirror-dest
            self.send_config([
                f"mirror mirror-dest {self.mirror_id}",
                "no shutdown",
                "exit",
            ], debug=True)

            # Configure mirror source using debug command
            print("[3/6] Configuring mirror source ...")
            self._send_and_wait("exit all", timeout=5)
            debug_cmds = [
                f"debug mirror-source {self.mirror_id}",
                f"port {interface} ingress egress",
                "no shutdown",
                "exit",
            ]
            for cmd in debug_cmds:
                output = self._send_and_wait(cmd, timeout=10)
                if "Error:" in output or "MINOR:" in output:
                    if "MINOR:" in output and "not found" not in output.lower():
                        print(f"    [!] {cmd}: {output.strip()[-80:]}")
        else:
            # MD-CLI syntax
            self.send_config([
                f"mirror mirror-dest {self.mirror_id} admin-state enable",
                f'mirror mirror-dest {self.mirror_id} pcap "{self.pcap_session}" file-url "{file_url}"',
                f"mirror mirror-source {self.mirror_id} admin-state enable",
                f"mirror mirror-source {self.mirror_id} port {interface} ingress true",
                f"mirror mirror-source {self.mirror_id} port {interface} egress true",
            ], debug=True)

        # Verify mirror config
        output = self.send_command(f"show mirror mirror-dest {self.mirror_id}")
        if "Admin" in output or "mirror" in output.lower():
            print("    Mirror destination verified")
        else:
            print("    [!] Warning: Mirror destination may not be properly configured")

        print(f"    Mirror ID: {self.mirror_id}")
        print(f"    Port: {interface}")
        print(f"    Local file: {self.pcap_remote_file}")
        return True

    def start_capture(self):
        """Start packet capture using debug pcap command."""
        cli_mode = getattr(self, 'cli_mode', 'classic')

        if cli_mode == "classic":
            # Classic CLI: debug pcap <session-name> capture start
            cmd = f'debug pcap {self.pcap_session} capture start'
        else:
            # MD-CLI: debug mirror-dest <id> pcap capture-start
            cmd = f'debug mirror-dest {self.mirror_id} pcap capture-start'

        output = self._send_and_wait(cmd, timeout=10)

        if "MINOR" in output or "error" in output.lower() or "invalid" in output.lower():
            print(f"    [!] Warning: capture-start may have failed")
            print(f"    [!] Output: {output.strip()[:200]}")
        else:
            print(f"    capture-start: OK")

    def stop_capture(self):
        """Stop packet capture using debug pcap command."""
        cli_mode = getattr(self, 'cli_mode', 'classic')

        if cli_mode == "classic":
            # Classic CLI: debug pcap <session-name> capture stop
            cmd = f'debug pcap {self.pcap_session} capture stop'
        else:
            # MD-CLI: debug mirror-dest <id> pcap capture-stop
            cmd = f'debug mirror-dest {self.mirror_id} pcap capture-stop'

        output = self._send_and_wait(cmd, timeout=10)

        if "MINOR" in output or "error" in output.lower():
            print(f"    [!] Warning: capture-stop may have failed")
        else:
            print(f"    capture-stop: OK")

    def get_capture_stats(self):
        """Get capture statistics."""
        cli_mode = getattr(self, 'cli_mode', 'classic')

        if cli_mode == "classic":
            # Classic CLI: show pcap <session-name> detail
            output = self.send_command(f"show pcap {self.pcap_session} detail")
        else:
            # MD-CLI: show debug mirror-dest
            output = self.send_command(f"show debug mirror-dest {self.mirror_id}")
            if "not found" in output.lower() or "invalid" in output.lower():
                output = self.send_command(f"admin show configuration /configure mirror")
        return output

    def download_pcap(self, remote_filename, local_path):
        """Download pcap file via SFTP/SCP."""
        remote_file = f"{self.pcap_dir}/{remote_filename}"
        local_file = Path(local_path)

        # Try SFTP first
        sftp_commands = f"get {remote_file} {local_file}\nquit\n"
        batch_file = Path("/tmp/.sftp_batch_nokia")
        batch_file.write_text(sftp_commands)

        sftp_cmd = [
            "sftp",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            "-b", str(batch_file),
            f"{self.username}@{self.hostname}",
        ]

        try:
            subprocess.run(sftp_cmd, check=True, capture_output=True, timeout=120)
            batch_file.unlink(missing_ok=True)
            if local_file.exists():
                return str(local_file)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

        # Fallback to SCP
        scp_cmd = [
            "scp",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            f"{self.username}@{self.hostname}:{remote_file}",
            str(local_file),
        ]
        try:
            subprocess.run(scp_cmd, check=True, capture_output=True, timeout=120)
            if local_file.exists():
                return str(local_file)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass

        return None

    def cleanup(self, pcap_filename=None):
        """Remove mirror configuration and pcap files from the device."""
        cli_mode = getattr(self, 'cli_mode', 'classic')

        # Stop capture first if running
        if cli_mode == "classic":
            self._send_and_wait(f'debug pcap {self.pcap_session} capture stop', timeout=5)
            # Remove debug mirror-source
            self._send_and_wait(f'debug mirror-source {self.mirror_id} shutdown', timeout=5)
            self._send_and_wait(f'no debug mirror-source {self.mirror_id}', timeout=5)
        else:
            self._send_and_wait(f'debug mirror-dest {self.mirror_id} pcap capture-stop', timeout=5)
        time.sleep(1)

        # Delete mirror config
        if cli_mode == "classic":
            self.send_config([
                f"no mirror mirror-dest {self.mirror_id}",
            ])
            # Delete pcap file from device
            if pcap_filename:
                self.send_command(f"file del {self.pcap_dir}/{pcap_filename} force")
            self.send_command(f"file rd {self.pcap_dir} force")
        else:
            self.send_config([
                f"delete mirror mirror-source {self.mirror_id}",
                f"delete mirror mirror-dest {self.mirror_id}",
            ])
            if pcap_filename:
                self.send_command(f"file remove {self.pcap_dir}/{pcap_filename} force")
            self.send_command(f"file remove-directory {self.pcap_dir} force")

        # Stop FTP server if running
        self._stop_ftp_server()


def discover_system_ip_nokia(nokia_capture):
    """Wrapper for Nokia system IP discovery."""
    return nokia_capture.discover_system_ip()


def discover_isis_interfaces_nokia(nokia_capture):
    """Wrapper for Nokia ISIS interface discovery."""
    return nokia_capture.discover_isis_interfaces()


def run_nokia_capture(args, nokia_capture):
    """Nokia SROS: mirror/pcap capture.

    Nokia SROS pcap requires FTP/TFTP for packet capture on most devices.
    If --ftp-url is provided, uses FTP transfer. Otherwise tries local storage
    and provides guidance if not supported.
    """
    if not args.interface:
        # Default to first port or prompt user
        ports = nokia_capture.discover_ports()
        if ports:
            args.interface = list(ports.keys())[0]
            print(f"[*] No interface specified, using first port: {args.interface}")
        else:
            print("[!] No interface specified and no ports found. Use --interface")
            sys.exit(1)

    if not args.output:
        iface_safe = args.interface.replace("/", "-")
        args.output = f"{args.device}-{iface_safe}.pcap"

    # Ensure local_dir exists
    os.makedirs(args.local_dir, exist_ok=True)
    local_pcap = os.path.join(args.local_dir, args.output)
    pcap_filename = args.output

    print(f"[*] Interface: {args.interface}")
    print(f"[*] Duration:  {args.duration}s")
    print(f"[*] Output:    {local_pcap}")
    print()

    # Get FTP URL if provided
    ftp_url = getattr(args, 'ftp_url', None)

    # Setup - configures mirror for pcap capture
    setup_ok = nokia_capture.setup_capture(args.interface, pcap_filename, args.local_dir, ftp_url)

    if not setup_ok:
        # Setup failed (likely FTP required but not provided)
        print("[!] Capture setup failed. Nokia SROS requires FTP for pcap capture.")
        nokia_capture.cleanup(pcap_filename)
        sys.exit(1)

    # Start capture
    print(f"[4/6] Starting capture ({args.duration}s) ...")
    nokia_capture.start_capture()

    # Wait for duration
    if args.duration > 0:
        # Check status after first 5 seconds
        time.sleep(5)
        mid_stats = nokia_capture.send_command(f"show debug mirror-dest {nokia_capture.mirror_id}")
        for line in mid_stats.split("\n"):
            if any(kw in line for kw in ["State", "Packets", "Bytes", "Error", "File", "pcap"]):
                print(f"    {line.strip()}")

        for remaining in range(args.duration - 5, 0, -10):
            print(f"     {remaining}s remaining ...", end="\r")
            time.sleep(min(10, remaining))
        print("     Capture complete.           ")
    else:
        print("     Press Ctrl+C to stop capture...")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

    # Stop capture
    print("[5/6] Stopping capture ...")
    nokia_capture.stop_capture()
    time.sleep(2)  # Allow file to be written

    # Show stats
    stats = nokia_capture.get_capture_stats()
    for line in stats.split("\n"):
        if "Packets" in line or "Bytes" in line or "File" in line:
            print(f"    {line.strip()}")

    # Verify file exists on device (stored locally via device's own FTP server)
    cli_mode = getattr(nokia_capture, 'cli_mode', 'classic')
    if cli_mode == "classic":
        file_list = nokia_capture.send_command(f"file dir {nokia_capture.pcap_dir}")
    else:
        file_list = nokia_capture.send_command(f"file list {nokia_capture.pcap_dir}/")

    if pcap_filename in file_list:
        print(f"    [*] File exists on device: {nokia_capture.pcap_dir}/{pcap_filename}")
        # Download via SFTP
        print("[*] Downloading pcap via SFTP ...")
        result = nokia_capture.download_pcap(pcap_filename, local_pcap)
        if result:
            print(f"    Downloaded: {result}")
        else:
            print("[!] SFTP download failed. File may still be on router at:")
            print(f"    {nokia_capture.pcap_dir}/{pcap_filename}")
    else:
        print(f"[!] Pcap file not found on device")
        print(f"    {file_list}")

    # Cleanup device config
    print("[6/6] Cleaning up device configuration ...")
    if not args.keep_remote:
        nokia_capture.cleanup(pcap_filename)
    else:
        print("[*] Keeping remote configuration (--keep-remote)")

    return local_pcap

# ============================================================
# Command builders
# ============================================================

def build_tcpdump_cmd(args, remote_pcap):
    if getattr(args, "isis_capture", False):
        loopback = getattr(args, "loopback_ip", None)
        if loopback:
            bpf = f"'isis or (ip host {loopback})'"
        else:
            bpf = "isis"
        parts = ["tcpdump", "-eni", args.interface, bpf]
    else:
        parts = ["tcpdump", "-eni", args.interface, "ip", "host", args.host_filter]
        extra = []
        if args.port:
            extra.append(f"port {args.port}")
        if args.exclude_port:
            extra.append(f"not port {args.exclude_port}")
        if args.protocol:
            extra.append(args.protocol)
        if extra:
            parts.append("and " + " and ".join(extra))
    parts.extend(["-w", remote_pcap, "-C", str(args.max_size), "-W", "1"])
    if args.snap_len > 0:
        parts.extend(["-s", str(args.snap_len)])
    if args.packet_count > 0:
        parts.extend(["-c", str(args.packet_count)])
    return " ".join(parts)


def build_monitor_traffic_cmd(args, remote_filename):
    iface = args.interface or "lo0.0"
    parts = ["monitor traffic interface", iface, "no-resolve"]
    parts.append(f"write-file {remote_filename}")
    if args.snap_len > 0:
        parts.append(f"size {args.snap_len}")
    if args.packet_count > 0:
        parts.append(f"count {args.packet_count}")
    match_parts = []
    if args.host_filter and not getattr(args, "isis_capture", False):
        match_parts.append(f"host {args.host_filter}")
    if args.port:
        match_parts.append(f"port {args.port}")
    if args.exclude_port:
        match_parts.append(f"not port {args.exclude_port}")
    if args.protocol:
        match_parts.append(args.protocol)
    if getattr(args, "isis_capture", False):
        loopback = getattr(args, "loopback_ip", None)
        if loopback:
            match_parts.append(f"isis or host {loopback}")
        else:
            match_parts.append("isis")
    if match_parts:
        parts.append(f"matching \"{' and '.join(match_parts)}\"")
    return " ".join(parts)


# ============================================================
# CLI parsing
# ============================================================

def parse_args():
    p = argparse.ArgumentParser(description="Remote tcpdump/monitor-traffic on ArcOS and Juniper devices",
                                formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("-d", "--device", required=True, help="Device hostname (e.g. router1.lab, switch1.dc1)")
    p.add_argument("-u", "--username", default=None, help="SSH username (default: $DEVICE_USERNAME or $USER)")
    p.add_argument("-p", "--password", default=None, help="SSH/sudo password (prompted if not given)")
    p.add_argument("--vendor", choices=["arcos", "juniper", "arista", "nokia"], default=None,
                   help="Device vendor (auto-detected from hostname if omitted)")
    p.add_argument("--host-filter", default=None, help="IP address to filter (auto-detected from loopback0)")
    p.add_argument("--port", type=int, default=None, help="Optional port filter")
    p.add_argument("--interface", default=None, help="Capture interface (default: any/lo0.0)")
    p.add_argument("--duration", type=int, default=60, help="Capture duration in seconds (default: 60, 0=unlimited)")
    p.add_argument("--packet-count", type=int, default=100000, help="Max packets (default: 100000, 0=unlimited)")
    p.add_argument("--max-size", type=int, default=10, help="Max pcap size in MB (default: 10)")
    p.add_argument("--snap-len", type=int, default=0, help="Snap length bytes (0=full, 96=headers only)")
    p.add_argument("--output", default=None, help="Output filename (default: {device}.pcap)")
    p.add_argument("--remote-dir", default=None, help="Remote dir (default: /tmp for ArcOS, /var/tmp for Juniper)")
    p.add_argument("--keep-remote", action="store_true", help="Don't delete remote pcap after download")
    p.add_argument("--local-dir", default=".", help="Local save directory (default: cwd)")
    p.add_argument("--exclude-port", type=int, default=None, help="Port to exclude (e.g. 22)")
    p.add_argument("--protocol", default=None, help="Protocol filter (tcp, udp, icmp)")
    p.add_argument("--show-interfaces", action="store_true", help="Show ISIS interfaces, then exit")
    p.add_argument("--isis-interface", default=None, help="Capture on a specific ISIS interface")
    p.add_argument("--ospf-interface", default=None, help="Capture on a specific OSPF interface (Arista)")
    p.add_argument("--ftp-url", default=None,
                   help="Nokia: FTP URL for pcap transfer (format: ftp://user:pass@host/file.pcap)")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    return p.parse_args()


# ============================================================
# Main
# ============================================================

def main():
    args = parse_args()
    load_dotenv()

    if not args.username:
        env_user = os.environ.get("DEVICE_USERNAME", "").strip()
        if env_user:
            args.username = env_user
        else:
            default_user = os.environ.get("USER", "")
            args.username = input(f"SSH username [{default_user}]: ").strip() or default_user
    if not args.password:
        env_pass = os.environ.get("DEVICE_PASSWORD", "")
        if env_pass:
            args.password = env_pass
        else:
            args.password = getpass.getpass("SSH/sudo password: ")

    # Detect vendor
    vendor = args.vendor or detect_vendor_from_hostname(args.device)
    if not vendor:
        print(f"[!] Could not auto-detect vendor for '{args.device}'. Use --vendor arcos|juniper|arista|nokia")
        sys.exit(1)
    print(f"[*] Vendor: {vendor}")

    # =========================================================
    # Nokia SROS - uses paramiko directly
    # =========================================================
    if vendor == "nokia":
        print(f"[1/6] Connecting to {args.device} ...")
        nokia_capture = NokiaSROSCapture(args.device, args.username, args.password)
        try:
            nokia_capture.connect()
        except Exception as e:
            print(f"[!] Connection failed: {e}")
            sys.exit(1)

        # Detect CLI mode
        cli_mode = nokia_capture.detect_cli_mode()
        print(f"[*] CLI mode: {cli_mode}")

        # Discover system IP
        print("[*] Discovering system IP ...")
        system_ip = nokia_capture.discover_system_ip()
        if system_ip:
            print(f"[*] Found system IP: {system_ip}")
            args.host_filter = system_ip
        else:
            print("[!] Could not discover system IP")

        # Discover ISIS interfaces
        isis_ifaces = nokia_capture.discover_isis_interfaces()
        if isis_ifaces:
            print(f"[*] ISIS interfaces:")
            for iname, idata in isis_ifaces.items():
                peer = f" -> {idata['peer']}" if idata['peer'] else ""
                print(f"      {iname:<16} {peer}")

        if args.show_interfaces:
            # Also show all ports
            ports = nokia_capture.discover_ports()
            if ports:
                print(f"[*] All ports:")
                for port, data in list(ports.items())[:20]:
                    state = data.get('state', 'Unknown')
                    print(f"      {port:<16} {state}")
            nokia_capture.disconnect()
            sys.exit(0)

        # Handle --isis-interface
        if args.isis_interface:
            if args.isis_interface in isis_ifaces:
                args.interface = args.isis_interface
                print(f"[*] Capturing on ISIS interface: {args.isis_interface}")
            else:
                print(f"[!] Interface {args.isis_interface} not found in ISIS")
                print(f"    Available: {', '.join(isis_ifaces.keys()) if isis_ifaces else 'none'}")

        # Run Nokia capture
        print(f"[*] Device: {args.device} (Nokia SROS)")
        try:
            local_pcap = run_nokia_capture(args, nokia_capture)
        finally:
            nokia_capture.disconnect()

        if os.path.isfile(local_pcap):
            size = os.path.getsize(local_pcap)
            print(f"[*] Saved: {local_pcap} ({size:,} bytes)")
        else:
            print("[!] Transfer failed.")
            sys.exit(1)

        print()
        print("=" * 60)
        print(f"  Capture: {local_pcap}")
        print(f"  View:    wireshark {local_pcap}")
        print(f"           tcpdump -r {local_pcap} -nn")
        print("=" * 60)
        sys.exit(0)

    # =========================================================
    # Other vendors - use netmiko
    # =========================================================
    device_type = VENDOR_MAP[vendor]
    device_params = {
        "device_type": device_type,
        "host": args.device,
        "username": args.username,
        "password": args.password,
        "timeout": 30,
        "session_timeout": 60,
        "global_delay_factor": 2,
    }

    print(f"[1] SSH into {args.device} ...")
    try:
        net_connect = ConnectHandler(**device_params)
    except Exception as e:
        print(f"[!] SSH connection failed: {e}")
        sys.exit(1)

    # --- Discovery ---
    if vendor == "juniper":
        if not args.host_filter:
            print("[*] Discovering lo0.0 IP ...")
            ip = discover_loopback_ip_junos(net_connect)
            if ip:
                args.host_filter = ip
                print(f"[*] Found lo0.0: {ip}")
            else:
                print("[!] Could not discover lo0.0 IP. Use --host-filter.")
                net_connect.disconnect()
                sys.exit(1)

        isis_ifaces = discover_isis_interfaces_junos(net_connect)
    elif vendor == "arista":
        if not args.host_filter:
            print("[*] Discovering Loopback0 IP ...")
            ip = discover_loopback_ip_arista(net_connect)
            if ip:
                args.host_filter = ip
                print(f"[*] Found Loopback0: {ip}")
            else:
                print("[!] Could not discover Loopback0 IP. Use --host-filter.")
                net_connect.disconnect()
                sys.exit(1)

        isis_ifaces = discover_ospf_interfaces_arista(net_connect)
    else:
        if not args.host_filter:
            print("[*] Discovering loopback0 IP ...")
            ip = discover_loopback_ip_arcos(net_connect)
            if ip:
                args.host_filter = ip
                print(f"[*] Found loopback0: {ip}")
            else:
                print("[!] Could not discover loopback0 IP. Use --host-filter.")
                net_connect.disconnect()
                sys.exit(1)

        isis_ifaces = discover_isis_interfaces_arcos(net_connect)

    # Print interfaces
    if isis_ifaces:
        proto_label = "OSPF" if vendor == "arista" else "ISIS"
        print(f"[*] {proto_label} interfaces:")
        for iname, idata in isis_ifaces.items():
            peer = f" -> {idata['peer']}" if idata['peer'] else ""
            print(f"      {iname:<12} {idata['ip'] or 'N/A':<18} {peer}")

    if args.show_interfaces:
        net_connect.disconnect()
        sys.exit(0)

    # Handle --isis-interface / --ospf-interface
    args.isis_capture = False
    args.ospf_capture = False
    args.loopback_ip = args.host_filter
    if args.isis_interface:
        if args.isis_interface in isis_ifaces:
            args.isis_capture = True
            args.interface = args.isis_interface
            peer = isis_ifaces[args.isis_interface].get("peer", "")
            print(f"[*] Capturing on {args.isis_interface}" + (f" (peer: {peer})" if peer else ""))
        else:
            print(f"[!] Interface {args.isis_interface} not found. Available: {', '.join(isis_ifaces.keys())}")
            net_connect.disconnect()
            sys.exit(1)
    if args.ospf_interface:
        if args.ospf_interface in isis_ifaces:
            args.ospf_capture = True
            args.interface = args.ospf_interface
            peer = isis_ifaces[args.ospf_interface].get("peer", "")
            print(f"[*] Capturing OSPF on {args.ospf_interface}" + (f" (peer: {peer})" if peer else ""))
        else:
            print(f"[!] Interface {args.ospf_interface} not found. Available: {', '.join(isis_ifaces.keys())}")
            net_connect.disconnect()
            sys.exit(1)

    # Print capture info
    print(f"[*] Device:    {args.device} ({vendor})")
    print(f"[*] Interface: {args.interface or ('any' if vendor == 'arcos' else 'lo0.0')}")
    if args.ospf_capture:
        loopback = args.loopback_ip
        print(f"[*] Filter:    proto ospf or host {loopback}" if loopback else "[*] Filter:    proto ospf")
    elif args.isis_capture:
        loopback = args.loopback_ip
        print(f"[*] Filter:    isis or host {loopback}" if loopback else "[*] Filter:    isis")
    else:
        filt = f"host {args.host_filter}"
        if args.port: filt += f" and port {args.port}"
        if args.exclude_port: filt += f" and not port {args.exclude_port}"
        print(f"[*] Filter:    {filt}")
    print(f"[*] Duration:  {args.duration}s" if args.duration else "[*] Duration:  until packet count reached")

    # --- Capture ---
    if vendor == "juniper":
        local_pcap = run_juniper_capture(args, net_connect)
    elif vendor == "arista":
        local_pcap = run_arista_capture(args, net_connect)
    else:
        local_pcap = run_arcos_capture(args, net_connect)

    # Done
    net_connect.disconnect()

    if os.path.isfile(local_pcap):
        size = os.path.getsize(local_pcap)
        print(f"[*] Saved: {local_pcap} ({size:,} bytes)")
    else:
        print("[!] Transfer failed."); sys.exit(1)

    print()
    print("=" * 60)
    print(f"  Capture: {local_pcap}")
    print(f"  View:    wireshark {local_pcap}")
    print(f"           tcpdump -r {local_pcap} -nn")
    print("=" * 60)


if __name__ == "__main__":
    main()
