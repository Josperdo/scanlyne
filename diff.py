"""Compare two parsed nmap scan results and surface security-relevant changes.

Core idea:
    Given a baseline scan and a current scan for the same target, produce a
    structured diff that answers: "What changed, and should I care?"

    The comparison works at three levels:
        1. Host level   — new or disappeared hosts on the network
        2. Port level   — ports that opened or closed on a known host
        3. Service level — version or state changes on an existing port

    Each changed item carries a risk_hint: a short, plain-English note that
    gives the analyst just enough context to triage the change without
    opening a full threat model. Risk hints are not verdicts — they are
    starting points for investigation.

Hints for implementation:
    - Build dicts keyed by host address for O(1) lookups instead of nested loops:
        {h["address"]: h for h in scan_a.get("hosts", [])}
    - Python set operations are your friend:
        set_b - set_a  → items in B but not A (new)
        set_a - set_b  → items in A but not B (removed)
        set_a & set_b  → items in both (check for changes)
    - For port comparison, use (port_number, protocol) as a tuple key
      so port 80/tcp and 80/udp are treated as different entries
    - Pass each individual change through _assess_risk() to populate risk_hint
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
                    ...host_dict fields...,
                    "risk_hint": str,   # why this host appearing might matter
                }
            ],
            "removed_hosts": [
                {
                    ...host_dict fields...,
                    "risk_hint": str,   # why this host disappearing might matter
                }
            ],
            "changed_hosts": [
                {
                    "address": str,
                    "hostname": str,
                    "new_ports": [
                        {
                            ...port_dict fields...,
                            "risk_hint": str,
                        }
                    ],
                    "removed_ports": [
                        {
                            ...port_dict fields...,
                            "risk_hint": str,
                        }
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

    Hints:
        - Build address-keyed dicts from both scan host lists
        - Create sets of addresses from each dict's keys
        - Use set difference to find new and removed hosts
        - Use set intersection to find hosts in both, then call _compare_host_ports()
        - Only include a host in changed_hosts if it actually has differences
          (i.e., at least one of new_ports, removed_ports, or changed_services is non-empty)
        - Attach a risk_hint to each new/removed host via _assess_risk()
    """
    # TODO: Build address-keyed dicts from both scan host lists
    # TODO: Create sets of addresses from each dict's keys
    # TODO: Use set difference to find new and removed hosts
    # TODO: For each new host, attach risk_hint via _assess_risk({"type": "new_host", "host": host})
    # TODO: For each removed host, attach risk_hint via _assess_risk({"type": "removed_host", "host": host})
    # TODO: Use set intersection to find hosts in both — call _compare_host_ports() on each
    # TODO: Only append to changed_hosts if _compare_host_ports() returns non-empty diff sections
    # TODO: Return the complete diff dict
    pass


def _compare_host_ports(host_a: dict, host_b: dict) -> dict[str, Any]:
    """Compare ports between two snapshots of the same host.

    Args:
        host_a: Host dict from baseline scan.
        host_b: Host dict from current scan.

    Returns:
        Dict with address, hostname, new_ports, removed_ports, changed_services.
        Each entry in new_ports and removed_ports includes a risk_hint field.
        Each entry in changed_services includes a risk_hint field.

    Hints:
        - Build (port_number, protocol) keyed dicts for both hosts
        - Use set operations to find new/removed port keys
        - For ports present in both, compare state and service fields
          (state change: open→filtered is different from filtered→open)
        - Build the changed_services list for any port whose state or service differs
        - For each new port, call _assess_risk({"type": "new_port", "port": port_dict})
        - For each removed port, call _assess_risk({"type": "removed_port", "port": port_dict})
        - For each changed service, call _assess_risk({"type": "service_change", ...})
    """
    # TODO: Build (port, protocol) keyed dicts for host_a and host_b ports
    # TODO: Use set operations to find new/removed port keys
    # TODO: For ports in both, compare state and service fields
    # TODO: Attach risk_hint to each new/removed port and changed service via _assess_risk()
    # TODO: Return the complete per-host diff dict
    pass


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
        A non-empty string. If no specific concern is identified, return a
        neutral note like "No specific concern — verify this change is expected."

    Hints for implementation:
        - For new_host: any new device on the network is worth noting;
          check if it has ports in SENSITIVE_PORTS
        - For removed_host: could be normal (shutdown) or concerning (device pulled);
          neutral hint is fine unless the host had sensitive ports open
        - For new_port: check port_dict["port"] against SENSITIVE_PORTS;
          check if it falls in EPHEMERAL_RANGE; check if state is "open"
        - For removed_port: a formerly-open port closing is usually good news,
          but a filtered port may mean a firewall rule changed, not the service stopped
        - For service_change: a version change (old_service != new_service) on an
          internet-facing host may indicate an upgrade or a compromise;
          a state change from closed/filtered to open is higher priority
        - Return SENSITIVE_PORTS[port_number] as part of the hint when applicable
    """
    # TODO: Implement triage logic using SENSITIVE_PORTS and EPHEMERAL_RANGE
    # TODO: Return a plain-English string for each change type
    return "No specific concern — verify this change is expected."
