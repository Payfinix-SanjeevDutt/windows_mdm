from flask_jwt_extended import jwt_required
from app.services.azure_ad import AzureADService
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import Element
from flask import Blueprint, request, jsonify
import requests
# from app.models import Device, db
# from app.services.azure_ad import fetch_device_details
# from app.services.azure_ad import fetch_access_token

# device_bp = Blueprint('device', __name__, url_prefix='/devices')
device_blueprint = Blueprint('device', __name__)

@device_blueprint.route('/discovery.svc', methods=['POST'])
def discover():
    """Discovery endpoint for MDM enrollment."""
    return jsonify({"enrollment_url": "https://windowsmdm.sujanix.com/enroll"})

@device_blueprint.route('/auth/callback', methods=['POST'])
def auth_callback():
    """Handle Azure AD authentication callback."""
    code = request.json.get('code')
    tokens = AzureADService.exchange_code_for_token(code)
    return jsonify(tokens)

@device_blueprint.route('/enroll', methods=['POST'])
def enroll():
    """Handle device enrollment."""
    device_info = request.json
    print("device_info>>",device_info)
    # Process device enrollment
    return jsonify({"message": "Device enrolled successfully"})


@device_blueprint.route('/manage', methods=['POST'])
@jwt_required()
def manage():
    """Manage enrolled devices."""
    action = request.json.get('action')
    device_id = request.json.get('device_id')
    # Perform device management actions
    return jsonify({"message": f"Action {action} performed on device {device_id}"})

# @device_bp.route('/fetch', methods=['GET'])
# def fetch_devices_from_azure():
#     devices = fetch_device_details()
#     return jsonify(devices)









# @device_bp.route('/enrollmentserver/discovery.svc', methods=['POST'])
# def discovery_service():

#     try:
#         namespaces = {
#             's': "http://www.w3.org/2003/05/soap-envelope",
#             'a': "http://www.w3.org/2005/08/addressing",
#             'm': "http://schemas.microsoft.com/windows/management/2012/01/enrollment"
#         }
#         root = ET.fromstring(request.data)
#         body = root.find('s:Body', namespaces)
#         if body is None:
#             return jsonify({"error": "SOAP Body not found"}), 400
#         discover = body.find('m:Discover', namespaces)
#         if discover is None:
#             return jsonify({"error": "Discover element not found"}), 400

#         request_element = discover.find('m:request', namespaces)
#         if request_element is None:
#             return jsonify({"error": "Request element not found"}), 400

#         email_address = request_element.find('m:EmailAddress', namespaces).text
#         request_version = request_element.find('m:RequestVersion', namespaces).text
#         device_type = request_element.find('m:DeviceType', namespaces).text
#         app_version = request_element.find('m:ApplicationVersion', namespaces).text
#         os_edition = request_element.find('m:OSEdition', namespaces).text
        
#         device_data = {
#             "accountEnabled": True,
#             "deviceId": email_address,  
#             "displayName": device_type ,
#             "operatingSystem": "Windows",
#             "operatingSystemVersion": "10.0"
#         }
        
#         access_token = fetch_access_token()
#         response = requests.post(
#             "https://graph.microsoft.com/v1.0/devices",
#             headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
#             json=device_data
#         )
        
#         if response.status_code != 201:
#             return jsonify({"error": "Failed to register device in Azure AD", "details": response.json()}), 500
        
#         response_data = {
#             "message": "Enrollment successful and registered in Azure AD",
#             "email_address": email_address,
#             "device_type": device_type
#         }
#         return jsonify(response_data), 200

#     except Exception as e:
#         print(f"Error: {str(e)}")
#         return jsonify({"error": str(e)}), 400



# @device_bp.route('/mdm/enroll', methods=['POST'])
# def oma_dm_enroll():

#     try:
#         # Parse the SOAP envelope
#         namespaces = {
#             's': "http://www.w3.org/2003/05/soap-envelope",
#             'a': "http://www.w3.org/2005/08/addressing",
#             'm': "http://schemas.microsoft.com/windows/management/2012/01/enrollment"
#         }
#         root = ET.fromstring(request.data)
#         body = root.find('s:Body', namespaces)
#         if body is None:
#             return jsonify({"error": "SOAP Body not found"}), 400

#         discover = body.find('m:Discover', namespaces)
#         if discover is None:
#             return jsonify({"error": "Discover element not found"}), 400

#         request_element = discover.find('m:request', namespaces)
#         if request_element is None:
#             return jsonify({"error": "Request element not found"}), 400

#         email_address = request_element.find('m:EmailAddress', namespaces).text
#         request_version = request_element.find('m:RequestVersion', namespaces).text
#         device_type = request_element.find('m:DeviceType', namespaces).text
#         app_version = request_element.find('m:ApplicationVersion', namespaces).text
#         os_edition = request_element.find('m:OSEdition', namespaces).text
        
#         device_data = {
#             "accountEnabled": True,
#             "deviceId": email_address,  
#             "displayName": device_type ,
#             "operatingSystem": "Windows",
#             "operatingSystemVersion": "10.0"
#         }
        
#         access_token = fetch_access_token()
#         request.post("http://192.168.0.220:5000/devices/fetch")
#         response = requests.post(
#             "https://graph.microsoft.com/v1.0/devices",
#             headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
#             json=device_data
#         )
        
#         if response.status_code != 201:
#             return jsonify({"error": "Failed to register device in Azure AD", "details": response.json()}), 500
        
#         response_data = {
#             "message": "Enrollment successful and registered in Azure AD",
#             "email_address": email_address,
#             "device_type": device_type
#         }
#         return jsonify(response_data), 200

#     except Exception as e:
#         print(f"Error: {str(e)}")
#         return jsonify({"error": str(e)}), 400


# @device_bp.route('/<device_id>', methods=['GET'])
# def get_device(device_id):
#     device = Device.query.filter_by(device_id=device_id).first()
#     if not device:
#         return jsonify({"error": "Device not found"}), 404

#     return jsonify({"device": device.to_dict()})

# @device_bp.route('/fetch', methods=['GET'])
# def fetch_devices_from_azure():
#     devices = fetch_device_details()
#     return jsonify(devices)










#------------------------------sunil----------------------------

# DOMAIN = "@sujanix.com"

# def is_user_belong_to_tenant(email):
#     return email.endswith(DOMAIN)

# @device_bp.route('/check_user_tenant', methods=['POST'])
# def check_user_tenant():
#     email = request.json.get('email')
#     if not email:
#         return jsonify({"error": "Email not provided"}), 400

#     if is_user_belong_to_tenant(email):
#         return jsonify({"message": f"The email {email} belongs to your tenant."}), 200
#     else:
#         return jsonify({"message": f"The email {email} does not belong to your tenant."}), 200






