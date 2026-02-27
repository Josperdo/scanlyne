"""Compare two parsed nmap scan results and surface security-relevant changes.

The comparison works at three levels:
    1. Host level   — new or disappeared hosts on the network
    2. Port level   — ports that opened or closed on a known host
    3. Service level — version or state changes on an existing port

Each changed item carries a risk_hint: a short, plain-English note that
gives the analyst just enough context to triage the change without
opening a full threat model. Risk hints are not verdicts — they are
starting points for investigation.
"""

from typing import Any


# Ports that are worth flagging regardless of context.
# Not exhaustive — just enough to catch common surprises.
SENSITIVE_PORTS = {
    21: "FTP — plaintext file transfer",
    22: "SSH — remote shell access",
    23: "Telnet — plaintext remote shell",
    25: "SMTP — mail relay, often abused",
    445: "SMB — common ransomware vector",
    1433: "MSSQL — database, verify intentional exposure",
    1521: "Oracle DB — database, verify intentional exposure",
    3306: "MySQL — database, verify intentional exposure",
    3389: "RDP — remote desktop, frequent brute-force target",
    4444: "Common reverse shell port",
    5432: "PostgreSQL — database, verify intentional exposure",
    5900: "VNC — remote desktop, often unencrypted",
    6379: "Redis — often misconfigured with no auth",
    8080: "Alternate HTTP — may be an admin panel or debug server",
    8443: "Alternate HTTPS — verify what service is listening",
    27017: "MongoDB — often misconfigured with no auth",
}

# Port ranges that warrant a closer look.
EPHEMERAL_RANGE = (49152, 65535)  # Dynamic/private ports — unusual for services


def compare_scans(scan_a: dict[str, Any], scan_b: dict[str, Any]) -> dict[str, Any]:
    """Compare a baseline scan against a current scan and return a structured diff.

    Args:
        scan_a: Parsed output from the earlier (baseline) scan.
        scan_b: Parsed output from the later (current) scan.

    Returns:
        {
            "new_hosts": [
                {
                    "address": str, "hostname": str, "status": str,
                    "ports": [...],
                    "risk_hint": str,
                }
            ],
            "removed_hosts": [
                {
                    "address": str, "hostname": str, "status": str,
                    "ports": [...],
                    "risk_hint": str,
                }
            ],
            "changed_hosts": [
                {
                    "address": str,
                    "hostname": str,
                    "new_ports": [
                        {"port": int, "protocol": str, "state": str,
                         "service": str, "version": str, "risk_hint": str}
                    ],
                    "removed_ports": [
                        {"port": int, "protocol": str, "state": str,
                         "service": str, "version": str, "risk_hint": str}
                    ],
                    "changed_services": [
                        {
                            "port": int,
                            "protocol": str,
                            "old_state": str,
                            "new_state": str,
                            "old_service": str,
                            "new_service": str,
                            "risk_hint": str,
                        }
                    ],
                }
            ],
        }
    """
    hosts_a = {h["address"]: h for h in scan_a.get("hosts", [])}
    hosts_b = {h["address"]: h for h in scan_b.get("hosts", [])}

    addrs_a = set(hosts_a)
    addrs_b = set(hosts_b)

    new_hosts = []
    for addr in addrs_b - addrs_a:
        host = dict(hosts_b[addr])
        host["risk_hint"] = _assess_risk({"type": "new_host", "host": host})
        new_hosts.append(host)

    removed_hosts = []
    for addr in addrs_a - addrs_b:
        host = dict(hosts_a[addr])
        host["risk_hint"] = _assess_risk({"type": "removed_host", "host": host})
        removed_hosts.append(host)

    changed_hosts = []
    for addr in addrs_a & addrs_b:
        host_diff = _compare_host_ports(hosts_a[addr], hosts_b[addr])
        if host_diff["new_ports"] or host_diff["removed_ports"] or host_diff["changed_services"]:
            changed_hosts.append(host_diff)

    return {
        "new_hosts": new_hosts,
        "removed_hosts": removed_hosts,
        "changed_hosts": changed_hosts,
    }


def _compare_host_ports(host_a: dict, host_b: dict) -> dict[str, Any]:
    """Compare ports between two snapshots of the same host.

    Args:
        host_a: Host dict from baseline scan.
        host_b: Host dict from current scan.

    Returns:
        Dict with address, hostname, new_ports, removed_ports, changed_services.
        Each entry in new_ports and removed_ports includes a risk_hint field.
        Each entry in changed_services includes a risk_hint field.
    """
    ports_a = {(p["port"], p["protocol"]): p for p in host_a.get("ports", [])}
    ports_b = {(p["port"], p["protocol"]): p for p in host_b.get("ports", [])}

    keys_a = set(ports_a)
    keys_b = set(ports_b)

    new_ports = []
    for key in keys_b - keys_a:
        port = dict(ports_b[key])
        port["risk_hint"] = _assess_risk({"type": "new_port", "port": port})
        new_ports.append(port)

    removed_ports = []
    for key in keys_a - keys_b:
        port = dict(ports_a[key])
        port["risk_hint"] = _assess_risk({"type": "removed_port", "port": port})
        removed_ports.append(port)

    changed_services = []
    for key in keys_a & keys_b:
        pa = ports_a[key]
        pb = ports_b[key]
        if pa["state"] != pb["state"] or pa["service"] != pb["service"]:
            change = {
                "port": pa["port"],
                "protocol": pa["protocol"],
                "old_state": pa["state"],
                "new_state": pb["state"],
                "old_service": pa["service"],
                "new_service": pb["service"],
            }
            change["risk_hint"] = _assess_risk({"type": "service_change", **change})
            changed_services.append(change)

    return {
        "address": host_b["address"],
        "hostname": host_b.get("hostname", ""),
        "new_ports": new_ports,
        "removed_ports": removed_ports,
        "changed_services": changed_services,
    }


def _assess_risk(change: dict[str, Any]) -> str:
    """Return a short, plain-English risk hint for a given change.

    This is not a threat model. It is a first-pass triage note — a sentence
    that gives the analyst a reason to look closer or move on.

    Args:
        change: A dict describing the change. Expected shapes:
            {"type": "new_host",      "host": host_dict}
            {"type": "removed_host",  "host": host_dict}
            {"type": "new_port",      "port": port_dict}
            {"type": "removed_port",  "port": port_dict}
            {"type": "service_change",
             "port": int, "protocol": str,
             "old_state": str, "new_state": str,
             "old_service": str, "new_service": str}

    Returns:
        A non-empty string. If no specific concern is identified, returns
        "No specific concern — verify this change is expected."
    """
    change_type = change.get("type")

    if change_type == "new_host":
        host = change["host"]
        port_numbers = {p["port"] for p in host.get("ports", [])}
        sensitive = [SENSITIVE_PORTS[p] for p in port_numbers if p in SENSITIVE_PORTS]
        if sensitive:
            return f"New host with sensitive ports open: {'; '.join(sensitive)}. Verify this device is authorized."
        return "New host appeared on the network — verify this device is authorized."

    if change_type == "removed_host":
        host = change["host"]
        port_numbers = {p["port"] for p in host.get("ports", [])}
        sensitive = [SENSITIVE_PORTS[p] for p in port_numbers if p in SENSITIVE_PORTS]
        if sensitive:
            return f"Host disappeared. Previously had sensitive ports: {'; '.join(sensitive)}. Confirm intentional removal."
        return "Host no longer responds — could be a shutdown, network change, or unexpected removal."

    if change_type == "new_port":
        port = change["port"]
        port_num = port["port"]
        if port_num in SENSITIVE_PORTS:
            return f"New open port: {SENSITIVE_PORTS[port_num]}"
        if EPHEMERAL_RANGE[0] <= port_num <= EPHEMERAL_RANGE[1]:
            return f"Port {port_num} is in the ephemeral range — unusual for a listening service. Investigate what opened it."
        return f"Port {port_num} is now open — verify this service is expected."

    if change_type == "removed_port":
        port = change["port"]
        port_num = port["port"]
        old_state = port.get("state", "")
        if old_state == "filtered":
            return f"Port {port_num} was filtered and is now gone — a firewall rule may have changed, not the service itself."
        if port_num in SENSITIVE_PORTS:
            return f"Sensitive port closed: {SENSITIVE_PORTS[port_num]}. Verify the service was intentionally stopped."
        return f"Port {port_num} is no longer visible — service stopped or firewall rule changed."

    if change_type == "service_change":
        port_num = change.get("port")
        old_state = change.get("old_state", "")
        new_state = change.get("new_state", "")
        old_service = change.get("old_service", "")
        new_service = change.get("new_service", "")

        if old_state in ("closed", "filtered") and new_state == "open":
            hint = f"Port {port_num} changed from {old_state} to open — higher priority."
            if port_num in SENSITIVE_PORTS:
                hint += f" {SENSITIVE_PORTS[port_num]}"
            return hint

        if old_service != new_service and old_service and new_service:
            return f"Service on port {port_num} changed from '{old_service}' to '{new_service}' — may be an upgrade or unexpected substitution."

    return "No specific concern — verify this change is expected."
