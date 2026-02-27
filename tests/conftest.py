"""Shared fixtures and constants for the Scanlyne test suite."""

import base64
import os
import tempfile

import pytest

from app import create_app
from models import db as _db


# ---------------------------------------------------------------------------
# Test configuration
# ---------------------------------------------------------------------------

class TestConfig:
    TESTING = True
    SECRET_KEY = "test-secret"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SCAN_OUTPUT_DIR = os.path.join(tempfile.gettempdir(), "scanlyne_test_scans")


# ---------------------------------------------------------------------------
# XML fixtures reused across parser and route tests
# ---------------------------------------------------------------------------

MINIMAL_XML = """\
<?xml version="1.0"?>
<nmaprun args="nmap -sV 192.168.1.1" startstr="Mon Jan 1 12:00:00 2025">
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames><hostname name="router.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

EMPTY_HOSTS_XML = """\
<?xml version="1.0"?>
<nmaprun args="nmap -sn 10.0.0.0/24" startstr="Mon Jan 1 12:00:00 2025">
</nmaprun>
"""


# ---------------------------------------------------------------------------
# Core fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def app():
    """Fresh Flask app with an in-memory DB for each test."""
    flask_app = create_app(TestConfig)
    with flask_app.app_context():
        _db.create_all()
        yield flask_app
        _db.session.remove()
        _db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def minimal_xml():
    return MINIMAL_XML


# ---------------------------------------------------------------------------
# Auth fixtures — separate app instance created AFTER env vars are patched
# ---------------------------------------------------------------------------

@pytest.fixture
def auth_app(monkeypatch):
    """App instance with Basic Auth enabled via environment variables."""
    monkeypatch.setenv("SCANLYNE_USERNAME", "admin")
    monkeypatch.setenv("SCANLYNE_PASSWORD", "secret")
    flask_app = create_app(TestConfig)
    with flask_app.app_context():
        _db.create_all()
        yield flask_app
        _db.session.remove()
        _db.drop_all()


@pytest.fixture
def auth_client(auth_app):
    return auth_app.test_client()


# ---------------------------------------------------------------------------
# Helpers available to tests
# ---------------------------------------------------------------------------

def make_auth_header(username: str, password: str) -> dict:
    """Build an Authorization: Basic header dict."""
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}
