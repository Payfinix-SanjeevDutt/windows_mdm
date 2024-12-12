from app import db

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String, nullable=False, unique=True)
    device_name = db.Column(db.String, nullable=False)
    enrolled_at = db.Column(db.DateTime, server_default=db.func.now())
    compliance_status = db.Column(db.String, default='Unknown')

    def to_dict(self):
        return {
            "id": self.id,
            "device_id": self.device_id,
            "device_name": self.device_name,
            "enrolled_at": self.enrolled_at,
            "compliance_status": self.compliance_status
        }
