from app.routes.device import device_blueprint

def register_routes(app):
    app.register_blueprint(device_blueprint)
