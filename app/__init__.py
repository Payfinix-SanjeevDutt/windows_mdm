from flask import Flask
from app.config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

db = SQLAlchemy()
migrate = Migrate()

def create_app():
    app = Flask(__name__)
    # app.config.from_object('app.config.Config')
    app.config.from_object(Config)
    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    
    with app.app_context():

        # Register blueprints (routes)
        # from app.routes import register_routes
        # register_routes(app)
        from app.routes import device_bp
        app.register_blueprint(device_bp)

        return app
