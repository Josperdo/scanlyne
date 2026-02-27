"""Blueprint for viewing scan history and individual results."""

from flask import Blueprint, abort, render_template

from models import Scan, db

bp = Blueprint("results", __name__, url_prefix="/results")


@bp.route("/")
def list_scans():
    """Show all past scans ordered by most recent first."""
    scans = Scan.query.order_by(Scan.started_at.desc()).all()
    return render_template("results/list.html", scans=scans)


@bp.route("/<int:scan_id>")
def detail(scan_id: int):
    """Show full results for a single scan."""
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        abort(404)
    return render_template("results/detail.html", scan=scan)
