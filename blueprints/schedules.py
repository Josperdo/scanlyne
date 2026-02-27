"""Blueprint for managing recurring scan schedules."""

import logging
from datetime import datetime, timezone

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for

from models import Schedule, db
from scanner import validate_flags, validate_target

logger = logging.getLogger(__name__)

bp = Blueprint("schedules", __name__, url_prefix="/schedules")


@bp.route("/")
def list_schedules():
    """Show all configured schedules."""
    schedules = Schedule.query.order_by(Schedule.created_at.desc()).all()
    return render_template("schedules/list.html", schedules=schedules)


@bp.route("/new")
def new_schedule():
    """Render the create-schedule form."""
    return render_template("schedules/new.html")


@bp.route("/", methods=["POST"])
def create_schedule():
    """Validate and persist a new recurring schedule."""
    target = request.form.get("target", "").strip()
    flags = request.form.get("flags", "").strip()
    interval_raw = request.form.get("interval_minutes", "").strip()

    if not target:
        flash("Target is required.", "error")
        return redirect(url_for("schedules.new_schedule"))

    if not validate_target(target):
        flash("Invalid target format. Use an IP address, CIDR range, or hostname.", "error")
        return redirect(url_for("schedules.new_schedule"))

    valid, err = validate_flags(flags)
    if not valid:
        flash(f"Invalid flags: {err}", "error")
        return redirect(url_for("schedules.new_schedule"))

    try:
        interval_minutes = int(interval_raw)
        if interval_minutes < 1:
            raise ValueError
    except (ValueError, TypeError):
        flash("Interval must be a whole number of minutes (minimum 1).", "error")
        return redirect(url_for("schedules.new_schedule"))

    webhook_url = request.form.get("webhook_url", "").strip() or None
    if webhook_url and not (webhook_url.startswith("http://") or webhook_url.startswith("https://")):
        flash("Webhook URL must start with http:// or https://", "error")
        return redirect(url_for("schedules.new_schedule"))

    schedule = Schedule(
        target=target,
        flags=flags,
        interval_minutes=interval_minutes,
        webhook_url=webhook_url,
    )
    db.session.add(schedule)
    db.session.commit()

    logger.info("Schedule %d created: %s every %dm", schedule.id, target, interval_minutes)
    flash(f"Schedule created: {target} every {interval_minutes} minute(s).", "success")
    return redirect(url_for("schedules.list_schedules"))


@bp.route("/<int:schedule_id>/toggle", methods=["POST"])
def toggle_schedule(schedule_id: int):
    """Enable or disable a schedule."""
    schedule = db.session.get(Schedule, schedule_id)
    if schedule is None:
        abort(404)

    schedule.enabled = not schedule.enabled
    db.session.commit()

    state = "enabled" if schedule.enabled else "disabled"
    flash(f"Schedule #{schedule_id} {state}.", "success")
    return redirect(url_for("schedules.list_schedules"))


@bp.route("/<int:schedule_id>/delete", methods=["POST"])
def delete_schedule(schedule_id: int):
    """Permanently remove a schedule."""
    schedule = db.session.get(Schedule, schedule_id)
    if schedule is None:
        abort(404)

    db.session.delete(schedule)
    db.session.commit()

    logger.info("Schedule %d deleted", schedule_id)
    flash(f"Schedule #{schedule_id} deleted.", "success")
    return redirect(url_for("schedules.list_schedules"))
