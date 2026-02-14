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

Hints:
    - ET.parse() returns a tree, .getroot() gives you the root <nmaprun> element
    - .find("tagname") returns the first matching child (or None)
    - .findall("tagname") returns a list of all matching children
    - .get("attr", "default") reads an XML attribute safely
    - Break it into helper functions: one per level (scan info, host, port)
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
    pass
