"""Compare two parsed nmap scan results and highlight differences.

This module takes two dicts (output of parse_nmap_xml) and finds:
    1. New hosts — appeared in scan B but not scan A
    2. Removed hosts — in scan A but gone from scan B
    3. Changed hosts — same IP in both, but ports/services differ

Hints:
    - Build dicts keyed by host address for O(1) lookups instead of nested loops
    - Python set operations are your friend:
        set_b - set_a  → items in B but not A (new)
        set_a - set_b  → items in A but not B (removed)
        set_a & set_b  → items in both (check for changes)
    - For port comparison, use (port_number, protocol) as a tuple key
      so port 80/tcp and 80/udp are treated as different entries
"""

from typing import Any


def compare_scans(scan_a: dict[str, Any], scan_b: dict[str, Any]) -> dict[str, Any]:
    """Compare two parsed scan results and return a structured diff.

    Args:
        scan_a: Parsed output from the earlier (baseline) scan.
        scan_b: Parsed output from the later (current) scan.

    Returns:
        {
            "new_hosts": [host_dict, ...],
            "removed_hosts": [host_dict, ...],
            "changed_hosts": [
                {
                    "address": str,
                    "hostname": str,
                    "new_ports": [port_dict, ...],
                    "removed_ports": [port_dict, ...],
                    "changed_services": [
                        {
                            "port": int, "protocol": str,
                            "old_state": str, "new_state": str,
                            "old_service": str, "new_service": str,
                        }
                    ],
                }
            ],
        }
    """
    # TODO: Build address-keyed dicts from both scan host lists
    #       e.g., {h["address"]: h for h in scan_a.get("hosts", [])}
    # TODO: Create sets of addresses from each dict's keys
    # TODO: Use set difference to find new and removed hosts
    # TODO: Use set intersection to find hosts in both — compare their ports
    # TODO: Only include a host in changed_hosts if it actually has differences
    # TODO: Return the structured diff dict
    pass


def _compare_host_ports(host_a: dict, host_b: dict) -> dict[str, Any]:
    """Compare ports between two snapshots of the same host.

    Args:
        host_a: Host dict from baseline scan.
        host_b: Host dict from current scan.

    Returns:
        Dict with address, hostname, new_ports, removed_ports, changed_services.
    """
    # TODO: Build (port, protocol) keyed dicts for both hosts
    # TODO: Use set operations to find new/removed port keys
    # TODO: For ports present in both, compare state and service fields
    # TODO: Build the changed_services list for any port whose state or service differs
    # TODO: Return the complete diff dict for this host
    pass
