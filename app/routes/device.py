import xml.etree.ElementTree as ET
from xml.etree.ElementTree import Element
from flask import Blueprint, request, jsonify
import requests
from app.models import Device, db
from app.services.azure_ad import fetch_device_details
from app.services.azure_ad import fetch_access_token

device_bp = Blueprint('device', __name__, url_prefix='/devices')


# @device_bp.route('/mdm/discovery', methods=['POST'])
# def mdm_discovery():
#     response = {
#         "authentication": "none",  # Could be Basic or Certificates if required
#         "registration_endpoint": "http://192.168.0.221:5000/devices/mdm/enroll"
#     }
#     return jsonify(response), 200

@device_bp.route('/enrollmentserver/discovery.svc', methods=['POST'])
def discovery_service():
    # return jsonify({
    #     "message": "MDM Server Auto-Discovery",
    #     "mdm_server": "https://192.168.0.220:5000/devices/mdm/enroll"
    # }), 200
    # print("Raw Request Data:::::::::: ", request.data)

    try:
        # Parse the SOAP envelope
        namespaces = {
            's': "http://www.w3.org/2003/05/soap-envelope",
            'a': "http://www.w3.org/2005/08/addressing",
            'm': "http://schemas.microsoft.com/windows/management/2012/01/enrollment"
        }
        root = ET.fromstring(request.data)
        
        # Extract the <s:Body> section
        body = root.find('s:Body', namespaces)
        if body is None:
            return jsonify({"error": "SOAP Body not found"}), 400

        # Extract the <Discover> section
        discover = body.find('m:Discover', namespaces)
        if discover is None:
            return jsonify({"error": "Discover element not found"}), 400

        # Extract the request details
        request_element = discover.find('m:request', namespaces)
        if request_element is None:
            return jsonify({"error": "Request element not found"}), 400

        email_address = request_element.find('m:EmailAddress', namespaces).text
        request_version = request_element.find('m:RequestVersion', namespaces).text
        device_type = request_element.find('m:DeviceType', namespaces).text
        app_version = request_element.find('m:ApplicationVersion', namespaces).text
        os_edition = request_element.find('m:OSEdition', namespaces).text
        
        device_data = {
            "accountEnabled": True,
            "deviceId": email_address,  
            "displayName": device_type ,
            "operatingSystem": "Windows",
            "operatingSystemVersion": "10.0"
        }
        
      
        
        access_token = fetch_access_token()
        # print("TOKEN>", access_token)
        response = requests.post(
            "https://graph.microsoft.com/v1.0/devices",
            headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
            json=device_data
        )
        
        print(" URL__response//////",  response)

        if response.status_code != 201:
            return jsonify({"error": "Failed to register device in Azure AD", "details": response.json()}), 500
        
        response_data = {
            "message": "Enrollment successful and registered in Azure AD",
            "email_address": email_address,
            "device_type": device_type
        }
        return jsonify(response_data), 200

        # response = {
        #     "message": "Enrollment successful",
        #     "email_address": email_address,
        #     "device_type": device_type,
        #     "mdm_server": "http://192.168.0.218:5000/mdm"
        # }
        # print("RES>>>>>>>>>>", response)  # Corrected
        # return jsonify(response), 200

    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"error": str(e)}), 400



@device_bp.route('/mdm/enroll', methods=['POST'])
def oma_dm_enroll():
    print("Raw Request Data:::::::::: ", request.data)

    try:
        # Parse the SOAP envelope
        namespaces = {
            's': "http://www.w3.org/2003/05/soap-envelope",
            'a': "http://www.w3.org/2005/08/addressing",
            'm': "http://schemas.microsoft.com/windows/management/2012/01/enrollment"
        }
        root = ET.fromstring(request.data)
        
        # Extract the <s:Body> section
        body = root.find('s:Body', namespaces)
        if body is None:
            return jsonify({"error": "SOAP Body not found"}), 400

        # Extract the <Discover> section
        discover = body.find('m:Discover', namespaces)
        if discover is None:
            return jsonify({"error": "Discover element not found"}), 400

        # Extract the request details
        request_element = discover.find('m:request', namespaces)
        if request_element is None:
            return jsonify({"error": "Request element not found"}), 400

        email_address = request_element.find('m:EmailAddress', namespaces).text
        request_version = request_element.find('m:RequestVersion', namespaces).text
        device_type = request_element.find('m:DeviceType', namespaces).text
        app_version = request_element.find('m:ApplicationVersion', namespaces).text
        os_edition = request_element.find('m:OSEdition', namespaces).text
        
        device_data = {
            "accountEnabled": True,
            "deviceId": email_address,  
            "displayName": device_type ,
            "operatingSystem": "Windows",
            "operatingSystemVersion": "10.0"
        }
        
      
        
        access_token = fetch_access_token()
        request.post("http://192.168.0.220:5000/devices/fetch")
        response = requests.post(
            "https://graph.microsoft.com/v1.0/devices",
            headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
            json=device_data
        )
        
        print(" URL__response//////",  response)

        if response.status_code != 201:
            return jsonify({"error": "Failed to register device in Azure AD", "details": response.json()}), 500
        
        response_data = {
            "message": "Enrollment successful and registered in Azure AD",
            "email_address": email_address,
            "device_type": device_type
        }
        return jsonify(response_data), 200

        # response = {
        #     "message": "Enrollment successful",
        #     "email_address": email_address,
        #     "device_type": device_type,
        #     "mdm_server": "http://192.168.0.218:5000/mdm"
        # }
        # print("RES>>>>>>>>>>", response)  # Corrected
        # return jsonify(response), 200

    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"error": str(e)}), 400


@device_bp.route('/<device_id>', methods=['GET'])
def get_device(device_id):
    device = Device.query.filter_by(device_id=device_id).first()
    if not device:
        return jsonify({"error": "Device not found"}), 404

    return jsonify({"device": device.to_dict()})

@device_bp.route('/fetch', methods=['GET'])
def fetch_devices_from_azure():
    devices = fetch_device_details()
    return jsonify(devices)
