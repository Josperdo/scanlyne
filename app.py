"""Flask application factory for the Scanlyne GUI."""

import logging
import os

from flask import Flask

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

    app.register_blueprint(scan_bp)
    app.register_blueprint(results_bp)
    app.register_blueprint(compare_bp)

    # Create database tables
    with app.app_context():
        db.create_all()

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
