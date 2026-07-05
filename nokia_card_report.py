#!/usr/bin/env python3
"""
bulk_card_and_file_report_html.py

Reads routers from my_routers.txt, prompts for SSH creds, then for each Nokia SROS device:

1) show card detail | no-more
2) file list | no-more

Produces:
- card_report.txt     (raw detail)
- file_lists.txt      (raw file list)
- report.html         (✅/⚠️ summary)

Uses send_command_timing() everywhere to avoid ReadTimeout on unexpected prompt strings.
"""

import re
import getpass
from netmiko import ConnectHandler, NetMikoTimeoutException, NetMikoAuthenticationException

# ——— CONFIGURATION ———
EXP_CF2_SIZE_MB = 3904
EXP_CF3_SIZE_MB = 7800
CF2_TOLERANCE   = 1
CF3_TOLERANCE   = 1
PCT_THRESHOLD   = 60

# Prompt for SSH creds
username = input("Username: ")
password = getpass.getpass("Password: ")

# Read routers
with open("my_routers.txt") as f:
    routers = [l.strip() for l in f if l.strip() and not l.startswith("#")]

# Containers
unreachable = []
not_equipped = []
raw_card   = []
raw_files  = []
summary    = []

# Regexes
r_card   = re.compile(r"^Card\b", re.IGNORECASE)
r_flash  = re.compile(r"^Flash\s*-\s*(cf[23])", re.IGNORECASE)
r_admin  = re.compile(r"Administrative State\s*:\s*(.+)", re.IGNORECASE)
r_op     = re.compile(r"Operational state\s*:\s*(.+)", re.IGNORECASE)
r_size   = re.compile(r"Size\s*:\s*([\d,]+)\s*MB", re.IGNORECASE)
r_pct    = re.compile(r"Percent Used\s*:\s*(\d+)\s*%", re.IGNORECASE)

def send(cmd, conn, host):
    """Helper: send via timing to avoid ReadTimeout."""
    out = conn.send_command_timing(cmd, strip_prompt=False, strip_command=False)
    print(f"[{host}] $ {cmd}")
    for line in out.splitlines():
        print(f"[{host}] {line}")
    return out

for host in routers:
    print(f"\n=== {host} ===")
    device = {
        "device_type": "nokia_sros",
        "host":        host,
        "username":    username,
        "password":    password,
        "timeout":     120,
    }
    try:
        conn = ConnectHandler(**device)
    except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
        print(f"[ERROR] {host} unreachable: {e}")
        unreachable.append(host)
        continue

    # — show card detail —
    card_out = send("show card detail | no-more", conn, host)
    raw_card.append(f"=== {host} ===\n{card_out}\n")

    # parse into summary record
    rec = {
        "device": host,
        **{f"cf{n}_{k}": "n/a" for n in (2,3) for k in ("size","pct","state")},
        **{f"cf{n}_{k}_ok": False for n in (2,3) for k in ("size","pct","state")},
    }
    missing = []
    current_flash = None

    for line in card_out.splitlines():
        s = line.strip()
        if not s:
            continue
        if r_card.match(s) or s.startswith("Hardware Data"):
            current_flash = None
            continue
        m = r_flash.match(s)
        if m:
            current_flash = m.group(1).lower()  # "cf2"/"cf3"
            continue
        if not current_flash:
            continue

        # admin
        m = r_admin.search(s)
        if m:
            st = m.group(1).strip().lower()
            rec[f"{current_flash}_state"] = st
            rec[f"{current_flash}_state_ok"] = (st == "up")
            if "not equip" in st:
                missing.append(current_flash)
            continue
        # op
        m = r_op.search(s)
        if m:
            st = m.group(1).strip().lower()
            rec[f"{current_flash}_state"] = st
            rec[f"{current_flash}_state_ok"] = (st == "up")
            if "not equip" in st:
                missing.append(current_flash)
            continue
        # size
        m = r_size.search(s)
        if m:
            sz = int(m.group(1).replace(",", ""))
            rec[f"{current_flash}_size"] = f"{sz} MB"
            tol = CF2_TOLERANCE if current_flash=="cf2" else CF3_TOLERANCE
            exp = EXP_CF2_SIZE_MB if current_flash=="cf2" else EXP_CF3_SIZE_MB
            rec[f"{current_flash}_size_ok"] = abs(sz-exp) <= tol
            continue
        # pct
        m = r_pct.search(s)
        if m:
            pct = int(m.group(1))
            rec[f"{current_flash}_pct"] = f"{pct} %"
            rec[f"{current_flash}_pct_ok"] = (pct < PCT_THRESHOLD)
            continue

    if missing:
        not_equipped.append((host, missing))
    summary.append(rec)

    # — file list —
    fl = send("file list | no-more", conn, host)
    raw_files.append(f"=== {host} ===\n{fl}\n")

    conn.disconnect()

# Write raw dumps
with open("card_report.txt", "w") as f:
    f.write("\n".join(raw_card))
print("→ card_report.txt")

with open("file_lists.txt", "w") as f:
    f.write("\n".join(raw_files))
print("→ file_lists.txt")

# Build HTML
html = [
    "<!DOCTYPE html>",
    "<html><head><meta charset='utf-8'><title>CF Card Summary</title>",
    "<style>",
    " body { font-family: sans-serif; padding:1em }",
    " table { border:1px solid #aaa; border-collapse: collapse; width:100% }",
    " th,td { border:1px solid #aaa; padding:6px; text-align:center }",
    " th { background:#eee }",
    " .ok   { background:#d4edda; color:#155724 }",
    " .warn { background:#fff3cd; color:#856404 }",
    " .fail { background:#f8d7da; color:#721c24 }",
    "</style>",
    "</head><body>",
    "<h1>CF Card Summary</h1>",
    "<table>",
    "<tr><th>Device</th>"
    "<th>CF2 Size</th><th>CF2 Util %</th><th>CF2 State</th>"
    "<th>CF3 Size</th><th>CF3 Util %</th><th>CF3 State</th></tr>"
]

for r in summary:
    row = [f"<td>{r['device']}</td>"]
    for cf in ("cf2","cf3"):
        for key,label in ((f"{cf}_size","Size"),(f"{cf}_pct","Util"),(f"{cf}_state","State")):
            val = r[key]
            ok = r[f"{key}_ok"]
            if "not equip" in val.lower():
                cls,icon = "warn","⚠️"
            elif ok:
                cls,icon = "ok","✅"
            else:
                cls,icon = "fail","⚠️"
            row.append(f"<td class='{cls}'>{val} {icon}</td>")
    html.append("<tr>" + "".join(row) + "</tr>")

html.extend([
    "</table>",
    "<h2>Unreachable</h2>",
    "<ul>" + "".join(f"<li>{h}</li>" for h in unreachable) + "</ul>",
    "<h2>Not-Equipped</h2>",
    "<ul>" + "".join(f"<li>{h}: {','.join(m)}</li>" for h,m in not_equipped) + "</ul>",
    "</body></html>"
])

with open("report.html","w") as f:
    f.write("\n".join(html))
print("→ report.html written")

# Console summary
print("\n=== SUMMARY ===")
print("Unreachable:", ", ".join(unreachable) or "None")
print("Not-Equipped:", 
      ", ".join(f"{h}({','.join(m)})" for h,m in not_equipped) or "None")
