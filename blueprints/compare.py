"""Blueprint for comparing two scans and viewing differences.

Hints:
    - The select page shows a form with two dropdowns of completed scans
    - The POST handler reads scan_a and scan_b IDs from the form
    - You need to validate: both selected, not the same, both exist, both have XML
    - Use parse_nmap_xml() on each scan's xml_file_path, then compare_scans()
    - Pass scan_a, scan_b, and the diff dict to the template
"""

from flask import Blueprint, flash, redirect, render_template, request, url_for

from diff import compare_scans
from models import Scan
from parser import parse_nmap_xml

bp = Blueprint("compare", __name__, url_prefix="/compare")


@bp.route("/")
def select():
    """Render the scan selection form for comparison."""
    # TODO: Query only completed scans, ordered by most recent
    # TODO: Render "compare/select.html" with the scans list
    pass


@bp.route("/", methods=["POST"])
def run_diff():
    """Compare two selected scans and display the diff.

    Validation steps:
        1. Both scan_a and scan_b must be selected
        2. They must be different scans
        3. Both must exist in the database
        4. Both must have xml_file_path set
    """
    # TODO: Read scan_a and scan_b IDs from request.form
    # TODO: Validate (redirect with flash on any failure):
    #       - Both IDs are present
    #       - They're not the same
    #       - Both scans exist in the DB
    #       - Both have xml_file_path
    # TODO: Parse both XML files with parse_nmap_xml()
    # TODO: Compare with compare_scans()
    # TODO: Handle FileNotFoundError/ValueError from parsing
    # TODO: Render "compare/diff.html" with scan_a, scan_b, and diff
    pass
