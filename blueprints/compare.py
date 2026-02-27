"""Blueprint for change detection — the primary view of Scanlyne.

Two comparison modes:
    - Baseline vs. latest: fast path; the app auto-selects a saved baseline
      and the most recent completed scan for the same target.
    - Manual: user picks any two completed scans from dropdowns.
"""

from flask import Blueprint, flash, redirect, render_template, request, url_for

from diff import compare_scans
from models import Scan, db
from parser import parse_nmap_xml

bp = Blueprint("compare", __name__, url_prefix="/compare")


@bp.route("/")
def select():
    """Render the change-detection landing page.

    Shows a "baseline vs. latest" quick-compare section (grouped by target)
    and a manual comparison form with two dropdowns.
    """
    scans = Scan.query.filter_by(status="completed").order_by(Scan.started_at.desc()).all()

    by_target: dict[str, list[Scan]] = {}
    for scan in scans:
        by_target.setdefault(scan.target, []).append(scan)

    quick_pairs = []
    for target_scans in by_target.values():
        baselines = [s for s in target_scans if s.is_baseline]
        non_baselines = [s for s in target_scans if not s.is_baseline]
        if not baselines or not non_baselines:
            continue
        latest = non_baselines[0]  # list is already ordered newest-first
        for baseline in baselines:
            quick_pairs.append({"baseline": baseline, "latest": latest})

    return render_template("compare/select.html", scans=scans, quick_pairs=quick_pairs)


@bp.route("/", methods=["POST"])
def run_diff():
    """Compare two selected scans and render the change-detection view.

    Validation steps:
        1. Both scan_a and scan_b must be selected
        2. They must be different scans
        3. Both must exist in the database
        4. Both must have xml_file_path set (i.e. nmap actually produced output)
    """
    scan_a_id = request.form.get("scan_a", "").strip()
    scan_b_id = request.form.get("scan_b", "").strip()

    if not scan_a_id or not scan_b_id:
        flash("Please select both scans to compare.", "error")
        return redirect(url_for("compare.select"))

    if scan_a_id == scan_b_id:
        flash("Select two different scans to compare.", "error")
        return redirect(url_for("compare.select"))

    try:
        scan_a = db.session.get(Scan, int(scan_a_id))
        scan_b = db.session.get(Scan, int(scan_b_id))
    except ValueError:
        flash("Invalid scan selection.", "error")
        return redirect(url_for("compare.select"))

    if scan_a is None or scan_b is None:
        flash("One or both selected scans could not be found.", "error")
        return redirect(url_for("compare.select"))

    if not scan_a.xml_file_path or not scan_b.xml_file_path:
        flash("One or both scans have no XML output to compare.", "error")
        return redirect(url_for("compare.select"))

    try:
        parsed_a = parse_nmap_xml(scan_a.xml_file_path)
        parsed_b = parse_nmap_xml(scan_b.xml_file_path)
    except (FileNotFoundError, ValueError) as e:
        flash(f"Could not read scan data: {e}", "error")
        return redirect(url_for("compare.select"))

    diff = compare_scans(parsed_a, parsed_b)
    return render_template("compare/diff.html", scan_a=scan_a, scan_b=scan_b, diff=diff)


@bp.route("/baseline-vs-latest", methods=["POST"])
def baseline_vs_latest():
    """Fast-path comparison: a specific baseline vs. the most recent completed scan.

    Reads a baseline_id from the form (supplied by the quick-compare table),
    then auto-selects the most recent non-baseline completed scan for the same
    target and runs the diff directly.
    """
    baseline_id = request.form.get("baseline_id", "").strip()

    if not baseline_id:
        flash("No baseline specified.", "error")
        return redirect(url_for("compare.select"))

    try:
        baseline = db.session.get(Scan, int(baseline_id))
    except ValueError:
        flash("Invalid baseline selection.", "error")
        return redirect(url_for("compare.select"))
    if baseline is None or not baseline.is_baseline:
        flash("Baseline scan not found.", "error")
        return redirect(url_for("compare.select"))

    latest = (
        Scan.query.filter_by(target=baseline.target, status="completed")
        .filter(Scan.id != baseline.id)
        .order_by(Scan.started_at.desc())
        .first()
    )
    if latest is None:
        flash(
            f"No newer completed scan found for {baseline.target} to compare against this baseline.",
            "error",
        )
        return redirect(url_for("compare.select"))

    try:
        parsed_a = parse_nmap_xml(baseline.xml_file_path)
        parsed_b = parse_nmap_xml(latest.xml_file_path)
    except (FileNotFoundError, ValueError) as e:
        flash(f"Could not read scan data: {e}", "error")
        return redirect(url_for("compare.select"))

    diff = compare_scans(parsed_a, parsed_b)
    return render_template("compare/diff.html", scan_a=baseline, scan_b=latest, diff=diff)
