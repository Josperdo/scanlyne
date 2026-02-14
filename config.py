import os


BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    """Base configuration."""

    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-change-me-in-production")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'scanner.db')}",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SCAN_OUTPUT_DIR = os.path.join(BASE_DIR, "scans")
