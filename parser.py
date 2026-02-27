"""Parse nmap XML output into structured Python data.

Nmap XML structure reference:
    <nmaprun args="nmap -sV 192.168.1.1" startstr="Mon Jan 1 12:00:00 2024" ...>
        <host>
            <status state="up"/>
            <address addr="192.168.1.1" addrtype="ipv4"/>
            <hostnames>
                <hostname name="router.local" type="PTR"/>
            </hostnames>
            <ports>
                <port protocol="tcp" portid="22">
                    <state state="open"/>
                    <service name="ssh" product="OpenSSH"/>
                </port>
            </ports>
        </host>
    </nmaprun>
"""

import os
import xml.etree.ElementTree as ET
from typing import Any


def parse_nmap_xml(file_path: str) -> dict[str, Any]:
    """Parse an nmap XML output file and return structured scan data.

    Args:
        file_path: Absolute or relative path to the nmap XML file.

    Returns:
        Dictionary with structure:
        {
            "scan_info": {
                "command": str,    # the nmap command that was run (from "args" attr)
                "start_time": str, # human-readable start time (from "startstr" attr)
            },
            "hosts": [
                {
                    "address": str,   # IP address
                    "hostname": str,  # resolved hostname (may be empty)
                    "status": str,    # "up" or "down"
                    "ports": [
                        {
                            "port": int,       # port number
                            "protocol": str,   # "tcp" or "udp"
                            "state": str,      # "open", "closed", "filtered"
                            "service": str,    # service name like "ssh", "http"
                            "version": str,    # product/version string
                        }
                    ]
                }
            ]
        }

    Raises:
        FileNotFoundError: If the XML file does not exist.
        ValueError: If the file cannot be parsed as valid XML.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"XML file not found: {file_path}")

    try:
        tree = ET.parse(file_path)
    except ET.ParseError as e:
        raise ValueError(f"Failed to parse nmap XML: {e}")

    root = tree.getroot()

    scan_info = {
        "command": root.get("args", ""),
        "start_time": root.get("startstr", ""),
    }

    hosts = []
    for host_elem in root.findall("host"):
        status_elem = host_elem.find("status")
        status = status_elem.get("state", "unknown") if status_elem is not None else "unknown"

        addr_elem = host_elem.find("address")
        address = addr_elem.get("addr", "") if addr_elem is not None else ""

        hostname = ""
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            hn = hostnames_elem.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")

        ports = []
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                state_elem = port_elem.find("state")
                port_state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

                service_elem = port_elem.find("service")
                service_name = ""
                service_version = ""
                if service_elem is not None:
                    service_name = service_elem.get("name", "")
                    product = service_elem.get("product", "")
                    version = service_elem.get("version", "")
                    service_version = f"{product} {version}".strip()

                ports.append({
                    "port": int(port_elem.get("portid", 0)),
                    "protocol": port_elem.get("protocol", "tcp"),
                    "state": port_state,
                    "service": service_name,
                    "version": service_version,
                })

        hosts.append({
            "address": address,
            "hostname": hostname,
            "status": status,
            "ports": ports,
        })

    return {
        "scan_info": scan_info,
        "hosts": hosts,
    }
