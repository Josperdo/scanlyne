"""Blueprint for viewing scan history and individual results.

Hints:
    - Scan.query gives you access to SQLAlchemy query methods
    - .order_by(Scan.started_at.desc()) sorts newest first
    - .all() returns a list, .get(id) returns one record or None
    - abort(404) returns a 404 page when a record isn't found
    - Pass variables to templates: render_template("page.html", scans=scans)
"""

from flask import Blueprint, abort, render_template

from models import Scan

bp = Blueprint("results", __name__, url_prefix="/results")


@bp.route("/")
def list_scans():
    """Show all past scans ordered by most recent first."""
    # TODO: Query all Scan records, ordered by started_at descending
    # TODO: Render "results/list.html" and pass the scans list
    pass


@bp.route("/<int:scan_id>")
def detail(scan_id: int):
    """Show full results for a single scan."""
    # TODO: Look up the Scan by id
    # TODO: Return 404 if not found
    # TODO: Render "results/detail.html" and pass the scan
    pass
