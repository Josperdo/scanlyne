"""Flask application factory for the Scanlyne GUI."""

import base64
import logging
import os
import threading
from datetime import datetime, timedelta, timezone

from flask import Flask, Response, render_template, request
from sqlalchemy import text

from config import Config
from models import db


def create_app(config_class: type = Config) -> Flask:
    """Create and configure the Flask application.

    Args:
        config_class: Configuration class to use.

    Returns:
        Configured Flask application instance.
    """
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Ensure instance and scan output directories exist
    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config["SCAN_OUTPUT_DIR"], exist_ok=True)

    # Initialize extensions
    db.init_app(app)

    # Register blueprints
    from blueprints.scan import bp as scan_bp
    from blueprints.results import bp as results_bp
    from blueprints.compare import bp as compare_bp
    from blueprints.schedules import bp as schedules_bp

    app.register_blueprint(scan_bp)
    app.register_blueprint(results_bp)
    app.register_blueprint(compare_bp)
    app.register_blueprint(schedules_bp)

    # Create database tables
    with app.app_context():
        db.create_all()
        # Add columns that were introduced after initial release.
        # db.create_all() only creates missing *tables*, not missing columns,
        # so we handle new columns with a safe ALTER TABLE.  The except swallows
        # "duplicate column" errors from SQLite when the column already exists.
        with db.engine.connect() as conn:
            try:
                conn.execute(text(
                    "ALTER TABLE schedules ADD COLUMN webhook_url VARCHAR(500)"
                ))
                conn.commit()
            except Exception:
                pass  # Column already present

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # ── HTTP Basic Auth ────────────────────────────────────────────────────────
    # Set SCANLYNE_USERNAME and SCANLYNE_PASSWORD environment variables to
    # enable single-user HTTP Basic Auth. When unset, the app is open (LAN-only
    # by design — use network-level access control as the primary boundary).
    auth_user = os.environ.get("SCANLYNE_USERNAME", "").strip()
    auth_pass = os.environ.get("SCANLYNE_PASSWORD", "").strip()

    if auth_user and auth_pass:
        @app.before_request
        def require_auth():
            header = request.headers.get("Authorization", "")
            if not header.startswith("Basic "):
                return Response(
                    "Authentication required.",
                    401,
                    {"WWW-Authenticate": 'Basic realm="Scanlyne"'},
                )
            try:
                decoded = base64.b64decode(header[6:]).decode("utf-8")
                req_user, req_pass = decoded.split(":", 1)
            except Exception:
                return Response(
                    "Authentication required.",
                    401,
                    {"WWW-Authenticate": 'Basic realm="Scanlyne"'},
                )
            if req_user != auth_user or req_pass != auth_pass:
                return Response(
                    "Authentication required.",
                    401,
                    {"WWW-Authenticate": 'Basic realm="Scanlyne"'},
                )

    # Register error handlers
    @app.errorhandler(404)
    def not_found(e):
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template("errors/500.html"), 500

    # ── Background scheduler ───────────────────────────────────────────────────
    # Only start in the main process. In debug+reloader mode werkzeug spawns a
    # child process (WERKZEUG_RUN_MAIN=true) — the scheduler starts there.
    # With gunicorn, use a single worker; multiple workers each get their own
    # scheduler and would fire duplicate scans.
    if not app.testing and (not app.debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true"):
        _start_scheduler(app)

    return app


def _start_scheduler(app: Flask) -> None:
    """Start the APScheduler background scheduler for recurring scans."""
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
    except ImportError:
        logging.getLogger(__name__).warning(
            "APScheduler not installed — scheduled scanning disabled. "
            "Run: pip install APScheduler"
        )
        return

    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(
        func=_check_scheduled_scans,
        trigger="interval",
        minutes=1,
        args=[app],
        id="scheduled_scan_checker",
        max_instances=1,  # skip if a previous check is still running
    )
    scheduler.start()
    logging.getLogger(__name__).info("Scan scheduler started.")


def _check_scheduled_scans(app: Flask) -> None:
    """Fire any schedules whose next_run_at is in the past.

    Called by APScheduler every minute. Launches each due scan in its own
    daemon thread so the scheduler job returns quickly.
    """
    from blueprints.scan import run_scan_background
    from models import Scan, Schedule, db

    with app.app_context():
        now = datetime.now(timezone.utc)
        due = (
            Schedule.query.filter_by(enabled=True)
            .filter(Schedule.next_run_at <= now)
            .all()
        )

        for schedule in due:
            scan = Scan(target=schedule.target, flags=schedule.flags, status="running")
            db.session.add(scan)
            db.session.commit()

            # Update timing before the thread starts so overlapping ticks skip it
            schedule.last_run_at = now
            schedule.next_run_at = now + timedelta(minutes=schedule.interval_minutes)
            db.session.commit()

            thread = threading.Thread(
                target=run_scan_background,
                args=(app, scan.id, app.config["SCAN_OUTPUT_DIR"]),
                kwargs={"webhook_url": schedule.webhook_url},
                daemon=True,
            )
            thread.start()
            logging.getLogger(__name__).info(
                "Scheduled scan %d started for %s", scan.id, schedule.target
            )


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
