"""Unit tests for diff.py — scan comparison and risk hint generation."""

from diff import compare_scans, _assess_risk


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _host(address, status="up", ports=None, hostname=""):
    return {"address": address, "hostname": hostname, "status": status, "ports": ports or []}


def _port(port, protocol="tcp", state="open", service="", version=""):
    return {"port": port, "protocol": protocol, "state": state, "service": service, "version": version}


def _scan(hosts):
    return {"scan_info": {}, "hosts": hosts}


# ---------------------------------------------------------------------------
# compare_scans
# ---------------------------------------------------------------------------

def test_identical_scans_no_changes():
    host = _host("192.168.1.1", ports=[_port(22, service="ssh")])
    scan = _scan([host])
    result = compare_scans(scan, scan)
    assert result["new_hosts"] == []
    assert result["removed_hosts"] == []
    assert result["changed_hosts"] == []


def test_both_scans_empty():
    result = compare_scans(_scan([]), _scan([]))
    assert result == {"new_hosts": [], "removed_hosts": [], "changed_hosts": []}


def test_new_host_detected():
    scan_a = _scan([_host("192.168.1.1")])
    scan_b = _scan([_host("192.168.1.1"), _host("10.0.0.99")])
    result = compare_scans(scan_a, scan_b)
    assert len(result["new_hosts"]) == 1
    assert result["new_hosts"][0]["address"] == "10.0.0.99"
    assert result["new_hosts"][0]["risk_hint"]


def test_removed_host_detected():
    scan_a = _scan([_host("192.168.1.1"), _host("192.168.1.2")])
    scan_b = _scan([_host("192.168.1.1")])
    result = compare_scans(scan_a, scan_b)
    assert len(result["removed_hosts"]) == 1
    assert result["removed_hosts"][0]["address"] == "192.168.1.2"


def test_new_port_detected():
    host_a = _host("192.168.1.1", ports=[_port(22)])
    host_b = _host("192.168.1.1", ports=[_port(22), _port(443)])
    result = compare_scans(_scan([host_a]), _scan([host_b]))
    new_port_nums = [p["port"] for p in result["changed_hosts"][0]["new_ports"]]
    assert 443 in new_port_nums


def test_removed_port_detected():
    host_a = _host("192.168.1.1", ports=[_port(22), _port(80)])
    host_b = _host("192.168.1.1", ports=[_port(22)])
    result = compare_scans(_scan([host_a]), _scan([host_b]))
    removed_port_nums = [p["port"] for p in result["changed_hosts"][0]["removed_ports"]]
    assert 80 in removed_port_nums


def test_service_change_detected():
    host_a = _host("192.168.1.1", ports=[_port(80, service="http")])
    host_b = _host("192.168.1.1", ports=[_port(80, service="https")])
    result = compare_scans(_scan([host_a]), _scan([host_b]))
    assert len(result["changed_hosts"][0]["changed_services"]) == 1
    svc = result["changed_hosts"][0]["changed_services"][0]
    assert svc["old_service"] == "http"
    assert svc["new_service"] == "https"


def test_state_change_detected():
    host_a = _host("192.168.1.1", ports=[_port(22, state="open")])
    host_b = _host("192.168.1.1", ports=[_port(22, state="filtered")])
    result = compare_scans(_scan([host_a]), _scan([host_b]))
    svc = result["changed_hosts"][0]["changed_services"][0]
    assert svc["old_state"] == "open"
    assert svc["new_state"] == "filtered"


def test_unchanged_host_not_in_changed():
    unchanged = _host("192.168.1.1", ports=[_port(22)])
    changed_a = _host("192.168.1.2", ports=[_port(80)])
    changed_b = _host("192.168.1.2", ports=[_port(80), _port(443)])
    result = compare_scans(_scan([unchanged, changed_a]), _scan([unchanged, changed_b]))
    changed_addrs = {h["address"] for h in result["changed_hosts"]}
    assert "192.168.1.1" not in changed_addrs
    assert "192.168.1.2" in changed_addrs


def test_tcp_and_udp_same_port_distinguished():
    host_a = _host("192.168.1.1", ports=[_port(80, protocol="tcp")])
    host_b = _host("192.168.1.1", ports=[_port(80, protocol="tcp"), _port(80, protocol="udp")])
    result = compare_scans(_scan([host_a]), _scan([host_b]))
    new_ports = result["changed_hosts"][0]["new_ports"]
    assert len(new_ports) == 1
    assert new_ports[0]["protocol"] == "udp"


# ---------------------------------------------------------------------------
# _assess_risk
# ---------------------------------------------------------------------------

def test_risk_new_host_with_sensitive_port():
    hint = _assess_risk({"type": "new_host", "host": _host("1.2.3.4", ports=[_port(22)])})
    assert "SSH" in hint


def test_risk_new_host_without_sensitive_port():
    hint = _assess_risk({"type": "new_host", "host": _host("1.2.3.4", ports=[_port(9999)])})
    assert "authorized" in hint


def test_risk_removed_host_with_sensitive_port():
    hint = _assess_risk({"type": "removed_host", "host": _host("1.2.3.4", ports=[_port(3389)])})
    assert "RDP" in hint


def test_risk_removed_host_without_sensitive_port():
    hint = _assess_risk({"type": "removed_host", "host": _host("1.2.3.4", ports=[_port(9999)])})
    assert hint  # non-empty


def test_risk_new_sensitive_port():
    hint = _assess_risk({"type": "new_port", "port": _port(3306)})
    assert "MySQL" in hint


def test_risk_new_ephemeral_port():
    hint = _assess_risk({"type": "new_port", "port": _port(50000)})
    assert "ephemeral" in hint


def test_risk_new_ordinary_port():
    hint = _assess_risk({"type": "new_port", "port": _port(8888)})
    assert hint  # non-empty, no specific category


def test_risk_removed_filtered_port():
    hint = _assess_risk({"type": "removed_port", "port": _port(9000, state="filtered")})
    assert "firewall" in hint


def test_risk_removed_sensitive_port():
    hint = _assess_risk({"type": "removed_port", "port": _port(22)})
    assert "SSH" in hint


def test_risk_service_change_closed_to_open():
    hint = _assess_risk({
        "type": "service_change",
        "port": 22, "protocol": "tcp",
        "old_state": "closed", "new_state": "open",
        "old_service": "ssh", "new_service": "ssh",
    })
    assert "higher priority" in hint


def test_risk_service_name_changed():
    hint = _assess_risk({
        "type": "service_change",
        "port": 80, "protocol": "tcp",
        "old_state": "open", "new_state": "open",
        "old_service": "http", "new_service": "https",
    })
    assert "changed from" in hint


def test_risk_unknown_type_returns_fallback():
    hint = _assess_risk({"type": "totally_unknown"})
    assert "No specific concern" in hint
