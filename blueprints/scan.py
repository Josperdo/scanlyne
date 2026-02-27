"""Blueprint for scan input and execution."""

import logging
import threading
from datetime import datetime, timezone

from flask import Blueprint, abort, current_app, flash, jsonify, redirect, render_template, request, url_for

from models import Host, Port, Scan, db
from parser import parse_nmap_xml
from scanner import run_scan, validate_flags, validate_target

logger = logging.getLogger(__name__)

bp = Blueprint("scan", __name__)


@bp.route("/")
def index():
    """Render the scan input form."""
    return render_template("scan/index.html")


@bp.route("/scan", methods=["POST"])
def start_scan():
    """Validate inputs, kick off a background scan, and redirect to the detail page."""
    target = request.form.get("target", "").strip()
    flags = request.form.get("flags", "").strip()

    if not target:
        flash("Target is required.", "error")
        return redirect(url_for("scan.index"))

    if not validate_target(target):
        flash("Invalid target format. Use an IP address, CIDR range, or hostname.", "error")
        return redirect(url_for("scan.index"))

    valid, err = validate_flags(flags)
    if not valid:
        flash(f"Invalid flags: {err}", "error")
        return redirect(url_for("scan.index"))

    scan = Scan(target=target, flags=flags, status="running")
    db.session.add(scan)
    db.session.commit()

    app = current_app._get_current_object()
    output_dir = app.config["SCAN_OUTPUT_DIR"]

    thread = threading.Thread(
        target=run_scan_background,
        args=(app, scan.id, output_dir),
        daemon=True,
    )
    thread.start()

    logger.info("Scan %d queued for target %s", scan.id, target)
    return redirect(url_for("results.detail", scan_id=scan.id))


@bp.route("/scan/<int:scan_id>/status")
def scan_status(scan_id: int):
    """Return the current status of a scan as JSON (used by the polling UI)."""
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        return jsonify({"status": "not_found"}), 404
    return jsonify({"status": scan.status, "scan_id": scan.id})


@bp.route("/scan/<int:scan_id>/set-baseline", methods=["POST"])
def set_baseline(scan_id: int):
    """Mark a completed scan as a named baseline for its target.

    Multiple baselines per target are allowed. An optional label can be
    provided to distinguish them (e.g. "pre-patch", "post-change").
    """
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        abort(404)

    if scan.status != "completed":
        flash("Only completed scans can be set as a baseline.", "error")
        return redirect(url_for("results.detail", scan_id=scan_id))

    label = request.form.get("label", "").strip() or None
    scan.is_baseline = True
    scan.label = label
    db.session.commit()

    label_str = f' "{label}"' if label else ""
    flash(f"Scan #{scan.id} is now a baseline{label_str} for {scan.target}.", "success")
    return redirect(url_for("results.detail", scan_id=scan.id))


def run_scan_background(app, scan_id: int, output_dir: str) -> None:
    """Execute a scan in a background thread and persist the results.

    Must be called in a daemon thread. Creates its own application context so
    it can safely use the database outside of a request.

    Args:
        app: The Flask application instance (not the proxy).
        scan_id: ID of the Scan record already created with status="running".
        output_dir: Directory to write nmap XML output.
    """
    with app.app_context():
        scan = db.session.get(Scan, scan_id)
        if scan is None:
            return
        try:
            xml_path = run_scan(scan.target, scan.flags, output_dir)
            parsed = parse_nmap_xml(xml_path)

            scan.xml_file_path = xml_path
            scan.completed_at = datetime.now(timezone.utc)
            scan.status = "completed"

            _store_parsed_results(scan, parsed)
            db.session.commit()
            logger.info("Scan %d completed for %s", scan_id, scan.target)

        except (ValueError, RuntimeError) as e:
            scan.status = "failed"
            db.session.commit()
            logger.error("Scan %d failed: %s", scan_id, e)


def _store_parsed_results(scan: Scan, parsed: dict) -> None:
    """Persist parsed nmap results into the database.

    Args:
        scan: The Scan model instance to associate results with.
        parsed: Output from parse_nmap_xml().
    """
    for host_data in parsed.get("hosts", []):
        host = Host(
            scan_id=scan.id,
            address=host_data["address"],
            hostname=host_data.get("hostname") or None,
            status=host_data.get("status", "up"),
        )
        db.session.add(host)
        db.session.flush()

        for port_data in host_data.get("ports", []):
            port = Port(
                host_id=host.id,
                port_number=port_data["port"],
                protocol=port_data.get("protocol", "tcp"),
                state=port_data.get("state", "open"),
                service_name=port_data.get("service") or None,
                service_version=port_data.get("version") or None,
            )
            db.session.add(port)
