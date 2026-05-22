"""Integration tests for all Flask blueprints.

Uses an in-memory SQLite DB and the Flask test client. run_scan_background is
patched wherever needed to prevent real nmap execution.
"""

import base64
import urllib.parse
from unittest import mock

import pytest

from conftest import MINIMAL_XML
from models import db, Scan, Schedule


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _auth_header(username, password):
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def _fresh(model_class, record_id):
    """Re-query a row, bypassing the session identity-map cache."""
    db.session.expire_all()
    return db.session.get(model_class, record_id)


# ---------------------------------------------------------------------------
# HTTP Basic Auth (Phase 3)
# ---------------------------------------------------------------------------

def test_no_auth_env_vars_allows_access(client):
    assert client.get("/").status_code == 200


def test_auth_blocks_unauthenticated(auth_client):
    resp = auth_client.get("/")
    assert resp.status_code == 401
    assert "WWW-Authenticate" in resp.headers


def test_auth_correct_credentials_allowed(auth_client):
    resp = auth_client.get("/", headers=_auth_header("admin", "secret"))
    assert resp.status_code == 200


def test_auth_wrong_password_rejected(auth_client):
    assert auth_client.get("/", headers=_auth_header("admin", "wrong")).status_code == 401


def test_auth_wrong_username_rejected(auth_client):
    assert auth_client.get("/", headers=_auth_header("notadmin", "secret")).status_code == 401


def test_auth_malformed_header_rejected(auth_client):
    resp = auth_client.get("/", headers={"Authorization": "Basic !!!"})
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Scan blueprint (Phase 1 + Phase 3 async)
# ---------------------------------------------------------------------------

def test_scan_index_renders(client):
    assert client.get("/").status_code == 200


def test_post_scan_valid_creates_record_and_redirects(client, app):
    with mock.patch("blueprints.scan.run_scan_background"):
        resp = client.post("/scan", data={"target": "192.168.1.1", "flags": "-sV"})
    assert resp.status_code == 302
    assert "/results/" in resp.headers["Location"]
    scan = Scan.query.filter_by(target="192.168.1.1").first()
    assert scan is not None
    assert scan.status == "running"


def test_post_scan_empty_target_flashes(client):
    resp = client.post("/scan", data={"target": "", "flags": ""}, follow_redirects=True)
    assert b"Target is required" in resp.data


def test_post_scan_invalid_target_flashes(client):
    # Manually encode so ';' becomes '%3B' — Werkzeug's EnvironBuilder leaves
    # ';' unencoded, causing it to be parsed as a field separator on the server.
    body = urllib.parse.urlencode({"target": "bad; rm", "flags": ""})
    resp = client.post(
        "/scan",
        data=body.encode(),
        content_type="application/x-www-form-urlencoded",
        follow_redirects=True,
    )
    assert b"Invalid target" in resp.data


def test_post_scan_invalid_flags_flashes(client):
    resp = client.post("/scan", data={"target": "192.168.1.1", "flags": "--script evil"}, follow_redirects=True)
    assert b"Invalid flags" in resp.data


def test_scan_status_returns_json(client, app):
    scan = Scan(target="192.168.1.1", flags="", status="running")
    db.session.add(scan)
    db.session.commit()
    scan_id = scan.id
    resp = client.get(f"/scan/{scan_id}/status")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "running"
    assert data["scan_id"] == scan_id


def test_scan_status_not_found(client):
    resp = client.get("/scan/9999/status")
    assert resp.status_code == 404
    assert resp.get_json()["status"] == "not_found"


def test_set_baseline_marks_completed_scan(client, app):
    scan = Scan(target="192.168.1.1", flags="", status="completed")
    db.session.add(scan)
    db.session.commit()
    scan_id = scan.id
    resp = client.post(f"/scan/{scan_id}/set-baseline", data={"label": "post-patch"})
    assert resp.status_code == 302
    updated = _fresh(Scan, scan_id)
    assert updated.is_baseline is True
    assert updated.label == "post-patch"


def test_set_baseline_without_label(client, app):
    scan = Scan(target="192.168.1.1", flags="", status="completed")
    db.session.add(scan)
    db.session.commit()
    scan_id = scan.id
    client.post(f"/scan/{scan_id}/set-baseline", data={"label": ""})
    updated = _fresh(Scan, scan_id)
    assert updated.is_baseline is True
    assert updated.label is None


def test_set_baseline_allows_multiple_per_target(client, app):
    """Phase 3: multiple baselines per target are now allowed."""
    s1 = Scan(target="192.168.1.1", flags="", status="completed")
    s2 = Scan(target="192.168.1.1", flags="", status="completed")
    db.session.add_all([s1, s2])
    db.session.commit()
    id1, id2 = s1.id, s2.id
    client.post(f"/scan/{id1}/set-baseline", data={"label": "alpha"})
    client.post(f"/scan/{id2}/set-baseline", data={"label": "beta"})
    db.session.expire_all()
    baselines = Scan.query.filter_by(target="192.168.1.1", is_baseline=True).all()
    assert len(baselines) == 2


def test_set_baseline_running_scan_rejected(client, app):
    scan = Scan(target="192.168.1.1", flags="", status="running")
    db.session.add(scan)
    db.session.commit()
    scan_id = scan.id
    resp = client.post(f"/scan/{scan_id}/set-baseline", follow_redirects=True)
    assert b"Only completed scans" in resp.data


def test_set_baseline_nonexistent_404(client):
    assert client.post("/scan/9999/set-baseline").status_code == 404


# ---------------------------------------------------------------------------
# Results blueprint (Phase 1)
# ---------------------------------------------------------------------------

def test_results_list_empty(client):
    assert client.get("/results/").status_code == 200


def test_results_list_shows_scans(client, app):
    s1 = Scan(target="10.0.0.1", flags="", status="completed")
    s2 = Scan(target="10.0.0.2", flags="", status="failed")
    db.session.add_all([s1, s2])
    db.session.commit()
    resp = client.get("/results/")
    assert b"10.0.0.1" in resp.data
    assert b"10.0.0.2" in resp.data


def test_results_detail_200(client, app):
    scan = Scan(target="192.168.1.1", flags="", status="completed")
    db.session.add(scan)
    db.session.commit()
    assert client.get(f"/results/{scan.id}").status_code == 200


def test_results_detail_running_state(client, app):
    scan = Scan(target="192.168.1.1", flags="", status="running")
    db.session.add(scan)
    db.session.commit()
    resp = client.get(f"/results/{scan.id}")
    assert resp.status_code == 200
    assert b"running" in resp.data


def test_results_detail_404(client):
    assert client.get("/results/9999").status_code == 404


# ---------------------------------------------------------------------------
# Compare blueprint (Phase 1 + Phase 3 multiple baselines)
# ---------------------------------------------------------------------------

def test_compare_select_renders(client):
    assert client.get("/compare/").status_code == 200


def test_compare_post_no_selection_flashes(client):
    resp = client.post("/compare/", data={}, follow_redirects=True)
    assert b"Please select both" in resp.data


def test_compare_post_same_scan_flashes(client, app):
    scan = Scan(target="192.168.1.1", flags="", status="completed", xml_file_path="/f.xml")
    db.session.add(scan)
    db.session.commit()
    scan_id = scan.id
    resp = client.post("/compare/", data={"scan_a": scan_id, "scan_b": scan_id}, follow_redirects=True)
    assert b"two different scans" in resp.data


def test_compare_post_missing_xml_flashes(client, app):
    s1 = Scan(target="192.168.1.1", flags="", status="completed", xml_file_path=None)
    s2 = Scan(target="192.168.1.1", flags="", status="completed", xml_file_path=None)
    db.session.add_all([s1, s2])
    db.session.commit()
    resp = client.post("/compare/", data={"scan_a": s1.id, "scan_b": s2.id}, follow_redirects=True)
    assert b"no XML output" in resp.data


def test_compare_post_valid_diff_renders(client, app, tmp_path):
    f1 = tmp_path / "s1.xml"
    f2 = tmp_path / "s2.xml"
    f1.write_text(MINIMAL_XML, encoding="utf-8")
    f2.write_text(MINIMAL_XML, encoding="utf-8")
    s1 = Scan(target="192.168.1.1", flags="", status="completed", xml_file_path=str(f1))
    s2 = Scan(target="192.168.1.1", flags="", status="completed", xml_file_path=str(f2))
    db.session.add_all([s1, s2])
    db.session.commit()
    resp = client.post("/compare/", data={"scan_a": s1.id, "scan_b": s2.id})
    assert resp.status_code == 200


def test_compare_post_xml_missing_on_disk_flashes(client, app):
    s1 = Scan(target="192.168.1.1", flags="", status="completed", xml_file_path="/nope1.xml")
    s2 = Scan(target="192.168.1.1", flags="", status="completed", xml_file_path="/nope2.xml")
    db.session.add_all([s1, s2])
    db.session.commit()
    resp = client.post("/compare/", data={"scan_a": s1.id, "scan_b": s2.id}, follow_redirects=True)
    assert b"Could not read" in resp.data


def test_baseline_vs_latest_no_id_flashes(client):
    resp = client.post("/compare/baseline-vs-latest", data={}, follow_redirects=True)
    assert b"No baseline specified" in resp.data


def test_baseline_vs_latest_non_baseline_scan_flashes(client, app):
    scan = Scan(target="192.168.1.1", flags="", status="completed", is_baseline=False)
    db.session.add(scan)
    db.session.commit()
    resp = client.post("/compare/baseline-vs-latest", data={"baseline_id": scan.id}, follow_redirects=True)
    assert b"Baseline scan not found" in resp.data


def test_baseline_vs_latest_no_newer_scan_flashes(client, app, tmp_path):
    f = tmp_path / "b.xml"
    f.write_text(MINIMAL_XML, encoding="utf-8")
    baseline = Scan(target="192.168.1.1", flags="", status="completed", is_baseline=True, xml_file_path=str(f))
    db.session.add(baseline)
    db.session.commit()
    resp = client.post("/compare/baseline-vs-latest", data={"baseline_id": baseline.id}, follow_redirects=True)
    assert b"No newer" in resp.data


def test_baseline_vs_latest_valid_renders(client, app, tmp_path):
    f1 = tmp_path / "b.xml"
    f2 = tmp_path / "l.xml"
    f1.write_text(MINIMAL_XML, encoding="utf-8")
    f2.write_text(MINIMAL_XML, encoding="utf-8")
    baseline = Scan(target="192.168.1.1", flags="", status="completed", is_baseline=True, xml_file_path=str(f1))
    latest = Scan(target="192.168.1.1", flags="", status="completed", is_baseline=False, xml_file_path=str(f2))
    db.session.add_all([baseline, latest])
    db.session.commit()
    resp = client.post("/compare/baseline-vs-latest", data={"baseline_id": baseline.id})
    assert resp.status_code == 200


def test_compare_quick_pairs_show_multiple_baselines(client, app, tmp_path):
    """Phase 3: each baseline per target gets its own row in the quick-compare table."""
    f = tmp_path / "scan.xml"
    f.write_text(MINIMAL_XML, encoding="utf-8")
    b1 = Scan(target="192.168.1.1", flags="", status="completed", is_baseline=True, label="alpha", xml_file_path=str(f))
    b2 = Scan(target="192.168.1.1", flags="", status="completed", is_baseline=True, label="beta", xml_file_path=str(f))
    non_b = Scan(target="192.168.1.1", flags="", status="completed", is_baseline=False, xml_file_path=str(f))
    db.session.add_all([b1, b2, non_b])
    db.session.commit()
    resp = client.get("/compare/")
    assert b"alpha" in resp.data
    assert b"beta" in resp.data


# ---------------------------------------------------------------------------
# Schedules blueprint (Phase 3)
# ---------------------------------------------------------------------------

def test_schedules_list_renders(client):
    assert client.get("/schedules/").status_code == 200


def test_schedules_new_form_renders(client):
    assert client.get("/schedules/new").status_code == 200


def test_create_schedule_valid(client, app):
    resp = client.post("/schedules/", data={"target": "10.0.0.1", "flags": "-sn", "interval_minutes": "60"})
    assert resp.status_code == 302
    s = Schedule.query.filter_by(target="10.0.0.1").first()
    assert s is not None
    assert s.interval_minutes == 60
    assert s.enabled is True


def test_create_schedule_empty_target_flashes(client):
    resp = client.post("/schedules/", data={"target": "", "flags": "", "interval_minutes": "60"}, follow_redirects=True)
    assert b"Target is required" in resp.data


def test_create_schedule_invalid_target_flashes(client):
    body = urllib.parse.urlencode({"target": "bad; cmd", "flags": "", "interval_minutes": "60"})
    resp = client.post(
        "/schedules/",
        data=body.encode(),
        content_type="application/x-www-form-urlencoded",
        follow_redirects=True,
    )
    assert b"Invalid target" in resp.data


def test_create_schedule_invalid_flags_flashes(client):
    resp = client.post("/schedules/", data={"target": "10.0.0.1", "flags": "--script evil", "interval_minutes": "60"}, follow_redirects=True)
    assert b"Invalid flags" in resp.data


def test_create_schedule_zero_interval_flashes(client):
    resp = client.post("/schedules/", data={"target": "10.0.0.1", "flags": "", "interval_minutes": "0"}, follow_redirects=True)
    assert b"Interval" in resp.data


def test_create_schedule_non_numeric_interval_flashes(client):
    resp = client.post("/schedules/", data={"target": "10.0.0.1", "flags": "", "interval_minutes": "abc"}, follow_redirects=True)
    assert b"Interval" in resp.data


def test_toggle_schedule_enabled_to_disabled(client, app):
    s = Schedule(target="10.0.0.1", flags="", interval_minutes=60, enabled=True)
    db.session.add(s)
    db.session.commit()
    s_id = s.id
    client.post(f"/schedules/{s_id}/toggle")
    assert _fresh(Schedule, s_id).enabled is False


def test_toggle_schedule_disabled_to_enabled(client, app):
    s = Schedule(target="10.0.0.1", flags="", interval_minutes=60, enabled=False)
    db.session.add(s)
    db.session.commit()
    s_id = s.id
    client.post(f"/schedules/{s_id}/toggle")
    assert _fresh(Schedule, s_id).enabled is True


def test_toggle_schedule_404(client):
    assert client.post("/schedules/9999/toggle").status_code == 404


def test_delete_schedule(client, app):
    s = Schedule(target="10.0.0.1", flags="", interval_minutes=60)
    db.session.add(s)
    db.session.commit()
    s_id = s.id
    client.post(f"/schedules/{s_id}/delete")
    db.session.expire_all()
    assert db.session.get(Schedule, s_id) is None


def test_delete_schedule_404(client):
    assert client.post("/schedules/9999/delete").status_code == 404


# ---------------------------------------------------------------------------
# Webhook — schedule creation and notification logic
# ---------------------------------------------------------------------------

def test_create_schedule_with_webhook_url(client, app):
    """A valid webhook URL is accepted and stored on the schedule."""
    resp = client.post("/schedules/", data={
        "target": "10.0.0.1",
        "flags": "",
        "interval_minutes": "60",
        "webhook_url": "https://hooks.example.com/notify",
    })
    assert resp.status_code == 302
    s = Schedule.query.filter_by(target="10.0.0.1").first()
    assert s.webhook_url == "https://hooks.example.com/notify"


def test_create_schedule_empty_webhook_url_stores_none(client, app):
    """An empty webhook URL field stores None (no notification)."""
    client.post("/schedules/", data={
        "target": "10.0.0.1", "flags": "", "interval_minutes": "60", "webhook_url": "",
    })
    s = Schedule.query.filter_by(target="10.0.0.1").first()
    assert s.webhook_url is None


def test_create_schedule_invalid_webhook_url_flashes(client):
    """A URL that doesn't start with http:// or https:// is rejected."""
    resp = client.post("/schedules/", data={
        "target": "10.0.0.1", "flags": "", "interval_minutes": "60",
        "webhook_url": "not-a-url",
    }, follow_redirects=True)
    assert b"http" in resp.data  # flash message mentions http/https


def test_fire_webhook_posts_json(app):
    """_fire_webhook makes a POST to the given URL with the payload as JSON."""
    from blueprints.scan import _fire_webhook
    with mock.patch("blueprints.scan.requests.post") as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.raise_for_status.return_value = None
        _fire_webhook("https://example.com/hook", {"event": "test"})
    mock_post.assert_called_once_with(
        "https://example.com/hook",
        json={"event": "test"},
        timeout=10,
    )


def test_fire_webhook_failure_does_not_raise(app):
    """A network error or bad response must never propagate — just log and continue."""
    from blueprints.scan import _fire_webhook
    with mock.patch("blueprints.scan.requests.post", side_effect=Exception("connection refused")):
        _fire_webhook("https://dead-endpoint.example.com/hook", {"event": "test"})
    # If we reach here without an exception, the test passes.


def test_notify_fires_when_changes_detected(app, tmp_path):
    """_notify_if_changes calls _fire_webhook when the diff is non-empty."""
    # Baseline: one host, one port
    baseline_xml = tmp_path / "baseline.xml"
    baseline_xml.write_text(MINIMAL_XML, encoding="utf-8")

    # Current scan: same host plus a new port (Redis on 6379)
    current_xml = tmp_path / "current.xml"
    current_xml.write_text("""\
<?xml version="1.0"?>
<nmaprun args="nmap -sV 192.168.1.1" startstr="Mon Jan 1 13:00:00 2025">
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames><hostname name="router.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
      <port protocol="tcp" portid="6379">
        <state state="open"/>
        <service name="redis"/>
      </port>
    </ports>
  </host>
</nmaprun>
""", encoding="utf-8")

    with app.app_context():
        from datetime import timezone
        from blueprints.scan import _notify_if_changes

        baseline = Scan(
            target="192.168.1.1", flags="", status="completed",
            is_baseline=True, xml_file_path=str(baseline_xml),
        )
        current = Scan(
            target="192.168.1.1", flags="", status="completed",
            is_baseline=False, xml_file_path=str(current_xml),
            completed_at=__import__("datetime").datetime.now(timezone.utc),
        )
        db.session.add_all([baseline, current])
        db.session.commit()

        with mock.patch("blueprints.scan._fire_webhook") as mock_fire:
            _notify_if_changes(current, "https://example.com/hook")

    mock_fire.assert_called_once()
    payload = mock_fire.call_args[0][1]
    assert payload["event"] == "scan_changes_detected"
    assert payload["changes"]["changed_hosts"] == 1  # port 6379 added


def test_notify_no_baseline_skips(app, tmp_path):
    """If there is no baseline for the target, the webhook must not fire."""
    xml = tmp_path / "scan.xml"
    xml.write_text(MINIMAL_XML, encoding="utf-8")

    with app.app_context():
        from blueprints.scan import _notify_if_changes
        scan = Scan(
            target="192.168.1.99", flags="", status="completed",
            xml_file_path=str(xml),
        )
        db.session.add(scan)
        db.session.commit()

        with mock.patch("blueprints.scan._fire_webhook") as mock_fire:
            _notify_if_changes(scan, "https://example.com/hook")

    mock_fire.assert_not_called()


def test_notify_no_changes_skips(app, tmp_path):
    """If the scan matches the baseline exactly, the webhook must not fire."""
    xml = tmp_path / "scan.xml"
    xml.write_text(MINIMAL_XML, encoding="utf-8")

    with app.app_context():
        from blueprints.scan import _notify_if_changes
        baseline = Scan(
            target="192.168.1.1", flags="", status="completed",
            is_baseline=True, xml_file_path=str(xml),
        )
        current = Scan(
            target="192.168.1.1", flags="", status="completed",
            is_baseline=False, xml_file_path=str(xml),
        )
        db.session.add_all([baseline, current])
        db.session.commit()

        with mock.patch("blueprints.scan._fire_webhook") as mock_fire:
            _notify_if_changes(current, "https://example.com/hook")

    mock_fire.assert_not_called()


# ---------------------------------------------------------------------------
# Error handlers (Phase 2)
# ---------------------------------------------------------------------------

def test_404_returns_custom_page(client):
    resp = client.get("/this/does/not/exist")
    assert resp.status_code == 404
    assert b"404" in resp.data
