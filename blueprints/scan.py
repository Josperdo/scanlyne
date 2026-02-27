"""Blueprint for scan input and execution.

Flask Blueprint concepts you'll use here:
    - Blueprint("name", __name__) creates a modular group of routes
    - @bp.route("/path") decorates a function to handle that URL
    - request.form.get("field") reads POST form data
    - flash("message", "category") shows one-time messages to the user
    - redirect(url_for("blueprint.function")) sends the user to another page
    - render_template("path.html", var=value) renders a Jinja2 template
    - current_app.config["KEY"] accesses app configuration
    - db.session.add(obj) / db.session.commit() persists to the database
    - db.session.flush() writes to DB without committing (gets auto-generated IDs)
"""

import logging
from datetime import datetime, timezone

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for

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
    """Validate inputs, run an nmap scan, and store results.

    Flow:
        1. Read target and flags from the submitted form
        2. Validate both (redirect back with flash message if invalid)
        3. Create a Scan record in the DB with status="running"
        4. Call run_scan() to execute nmap
        5. On success: parse XML, store hosts/ports, update status to "completed"
        6. On failure: update status to "failed", flash the error
        7. Redirect to the appropriate page
    """
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

    try:
        xml_path = run_scan(target, flags, current_app.config["SCAN_OUTPUT_DIR"])
        parsed = parse_nmap_xml(xml_path)

        scan.xml_file_path = xml_path
        scan.completed_at = datetime.now(timezone.utc)
        scan.status = "completed"

        _store_parsed_results(scan, parsed)
        db.session.commit()

        logger.info("Scan %d completed for target %s", scan.id, target)
        return redirect(url_for("results.detail", scan_id=scan.id))

    except (ValueError, RuntimeError) as e:
        scan.status = "failed"
        db.session.commit()
        flash(f"Scan failed: {e}", "error")
        logger.error("Scan %d failed: %s", scan.id, e)
        return redirect(url_for("scan.index"))


@bp.route("/scan/<int:scan_id>/set-baseline", methods=["POST"])
def set_baseline(scan_id: int):
    """Mark a completed scan as the baseline for its target.

    Promotes this scan to baseline status and clears the baseline flag from
    any previously-baselined scan for the same target. Only completed scans
    should be eligible.

    Flow:
        1. Look up the scan by scan_id (404 if not found)
        2. Verify scan.status == "completed" (flash error and redirect if not)
        3. Clear is_baseline on any existing baseline for the same target
        4. Set scan.is_baseline = True
        5. Commit, flash a success message, redirect to the scan's detail page
    """
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        abort(404)

    if scan.status != "completed":
        flash("Only completed scans can be set as a baseline.", "error")
        return redirect(url_for("results.detail", scan_id=scan_id))

    for existing in Scan.query.filter_by(target=scan.target, is_baseline=True).all():
        existing.is_baseline = False

    scan.is_baseline = True
    db.session.commit()

    flash(f"Scan #{scan.id} is now the baseline for {scan.target}.", "success")
    return redirect(url_for("results.detail", scan_id=scan.id))


def _store_parsed_results(scan: Scan, parsed: dict) -> None:
    """Persist parsed nmap results into the database.

    Args:
        scan: The Scan model instance to associate results with.
        parsed: Output from parse_nmap_xml().

    Hints:
        - Loop over parsed["hosts"] to create Host records
        - For each host, loop over its "ports" to create Port records
        - Use db.session.flush() after adding a Host to get its id
          before creating Port records that reference host.id
        - Map the parsed dict keys to the model field names:
            parsed "address" → Host.address
            parsed "port" → Port.port_number
            parsed "service" → Port.service_name
            parsed "version" → Port.service_version
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
