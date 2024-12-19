def validate_device_payload(payload):
    """Validate the device payload before enrollment."""
    required_keys = ['device_id', 'device_name']
    return all(key in payload for key in required_keys)