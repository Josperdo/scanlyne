from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()


class Scan(db.Model):
    """Represents a single nmap scan execution.

    Baseline scans serve as the reference point for change detection.
    Only one scan per target should be marked as the baseline at a time;
    enforcing that uniqueness is left to the application layer.
    """

    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(255), nullable=False)
    flags = db.Column(db.String(500), nullable=False, default="")
    started_at = db.Column(
        db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    completed_at = db.Column(db.DateTime, nullable=True)
    xml_file_path = db.Column(db.String(500), nullable=True)
    status = db.Column(
        db.String(20), nullable=False, default="pending"
    )  # pending, running, completed, failed

    # Change-detection fields
    is_baseline = db.Column(db.Boolean, nullable=False, default=False)
    label = db.Column(db.String(100), nullable=True)  # e.g. "post-patch baseline"

    hosts = db.relationship("Host", backref="scan", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        baseline_flag = " [baseline]" if self.is_baseline else ""
        return f"<Scan {self.id} target={self.target} status={self.status}{baseline_flag}>"


class Host(db.Model):
    """A host discovered during a scan."""

    __tablename__ = "hosts"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    address = db.Column(db.String(45), nullable=False)  # IPv4 or IPv6
    hostname = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(10), nullable=False, default="up")

    ports = db.relationship("Port", backref="host", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Host {self.address} status={self.status}>"


class Port(db.Model):
    """A port found on a host during a scan."""

    __tablename__ = "ports"

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey("hosts.id"), nullable=False)
    port_number = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), nullable=False, default="tcp")
    state = db.Column(db.String(20), nullable=False, default="open")
    service_name = db.Column(db.String(100), nullable=True)
    service_version = db.Column(db.String(200), nullable=True)

    def __repr__(self) -> str:
        return f"<Port {self.port_number}/{self.protocol} state={self.state}>"
