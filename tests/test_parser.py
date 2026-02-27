"""Unit tests for parser.py — nmap XML parsing."""

import pytest
from parser import parse_nmap_xml
from conftest import MINIMAL_XML, EMPTY_HOSTS_XML


@pytest.fixture
def xml_file(tmp_path, minimal_xml):
    f = tmp_path / "scan.xml"
    f.write_text(minimal_xml, encoding="utf-8")
    return str(f)


def test_parse_returns_expected_keys(xml_file):
    result = parse_nmap_xml(xml_file)
    assert "scan_info" in result
    assert "hosts" in result


def test_parse_scan_info(xml_file):
    result = parse_nmap_xml(xml_file)
    assert result["scan_info"]["command"] == "nmap -sV 192.168.1.1"
    assert result["scan_info"]["start_time"] == "Mon Jan 1 12:00:00 2025"


def test_parse_host_count(xml_file):
    result = parse_nmap_xml(xml_file)
    assert len(result["hosts"]) == 1


def test_parse_host_fields(xml_file):
    host = parse_nmap_xml(xml_file)["hosts"][0]
    assert host["address"] == "192.168.1.1"
    assert host["hostname"] == "router.local"
    assert host["status"] == "up"


def test_parse_port_fields(xml_file):
    ports = parse_nmap_xml(xml_file)["hosts"][0]["ports"]
    assert len(ports) == 2
    ssh = next(p for p in ports if p["port"] == 22)
    assert ssh["protocol"] == "tcp"
    assert ssh["state"] == "open"
    assert ssh["service"] == "ssh"
    assert "OpenSSH" in ssh["version"]


def test_parse_empty_hosts(tmp_path):
    f = tmp_path / "empty.xml"
    f.write_text(EMPTY_HOSTS_XML, encoding="utf-8")
    assert parse_nmap_xml(str(f))["hosts"] == []


def test_parse_host_no_hostname(tmp_path):
    xml = """\
<?xml version="1.0"?>
<nmaprun args="" startstr="">
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
  </host>
</nmaprun>
"""
    f = tmp_path / "nohostname.xml"
    f.write_text(xml, encoding="utf-8")
    assert parse_nmap_xml(str(f))["hosts"][0]["hostname"] == ""


def test_parse_host_no_ports(tmp_path):
    xml = """\
<?xml version="1.0"?>
<nmaprun args="" startstr="">
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
  </host>
</nmaprun>
"""
    f = tmp_path / "noports.xml"
    f.write_text(xml, encoding="utf-8")
    assert parse_nmap_xml(str(f))["hosts"][0]["ports"] == []


def test_parse_file_not_found():
    with pytest.raises(FileNotFoundError):
        parse_nmap_xml("/nonexistent/path/scan.xml")


def test_parse_invalid_xml(tmp_path):
    f = tmp_path / "bad.xml"
    f.write_text("not xml at all", encoding="utf-8")
    with pytest.raises(ValueError):
        parse_nmap_xml(str(f))


def test_parse_multiple_hosts(tmp_path):
    xml = """\
<?xml version="1.0"?>
<nmaprun args="" startstr="">
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
  </host>
  <host>
    <status state="up"/>
    <address addr="192.168.1.2" addrtype="ipv4"/>
  </host>
</nmaprun>
"""
    f = tmp_path / "multi.xml"
    f.write_text(xml, encoding="utf-8")
    result = parse_nmap_xml(str(f))
    addresses = {h["address"] for h in result["hosts"]}
    assert addresses == {"192.168.1.1", "192.168.1.2"}


def test_parse_filtered_port_state(tmp_path):
    xml = """\
<?xml version="1.0"?>
<nmaprun args="" startstr="">
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="filtered"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
    f = tmp_path / "filtered.xml"
    f.write_text(xml, encoding="utf-8")
    port = parse_nmap_xml(str(f))["hosts"][0]["ports"][0]
    assert port["state"] == "filtered"
