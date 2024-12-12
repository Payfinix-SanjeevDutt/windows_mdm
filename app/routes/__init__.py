from app.routes.device import device_bp

def register_routes(app):
    app.register_blueprint(device_bp)
