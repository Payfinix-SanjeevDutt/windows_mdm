from flask import Flask, request, jsonify, render_template
from utils.graph_api import enroll_device, list_devices
import xml.etree.ElementTree as ET
import requests
from xml.etree.ElementTree import Element

app = Flask(__name__)

@app.route("/")
def home():
    return jsonify({
        "message": "Welcome to theWindows MDM Server",
        "endpoints": {
            "discovery": "https://windowsmdm.sujanix.com/discover",
            "terms_of_use": "https://windowsmdm.sujanix.com/terms-of-use",
            "compliance": "https://windowsmdm.sujanix.com/compliance",
            "enrollment" : "https://windowsmdm.sujanix.com/enroll"
        },
       
    })


# Serve the Terms of Use
@app.route('/terms-of-use', methods=['GET'])
def terms_of_use():
    return render_template('terms_of_use.html')

# Compliance Status
@app.route('/compliance', methods=['GET'])
def compliance():
    # Simulate compliance data
    device_id = request.args.get("device_id")
    if not device_id:
        return jsonify({"error": "Device ID is required"}), 400
    
    # Example: Check compliance status (mocked for simplicity)
    compliance_status = {
        "device_id": device_id,
        "compliant": True,
        "details": "Device is compliant with all MDM policies."
    }
    return jsonify(compliance_status)

# MDM Discovery (Optional for Azure testing)
@app.route('/discover', methods=['GET'])
def mdm_discovery():
    print("HI")
    enrollment_url="https://windowsmdm.sujanix.com/enroll"
    requests.post(enrollment_url)
    
    return jsonify({
        "service_url": "https://windowsmdm.sujanix.com/enroll",
        "terms_of_use_url": "https://windowsmdm.sujanix.com/terms-of-use",
        "compliance_url": "https://windowsmdm.sujanix.com/compliance",
         "enrollment_url": "https://windowsmdm.sujanix.com/enroll"
    })

@app.route('/enroll', methods=['POST'])
def enroll():
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
    
    print("DEVICE_DATA????????????", request_element)

    email_address = request_element.find('m:EmailAddress', namespaces).text
    request_version = request_element.find('m:RequestVersion', namespaces).text
    device_type = request_element.find('m:DeviceType', namespaces).text
    app_version = request_element.find('m:ApplicationVersion', namespaces).text
    os_edition = request_element.find('m:OSEdition', namespaces).text
    # device_id = request_element.find('m:DeviceId', namespaces).text
    # print("device_id---", device_id)
    device_data = {
        "accountEnabled": True,
        "deviceId": email_address,  
        "displayName": device_type ,
        "operatingSystem": "Windows",
        "operatingSystemVersion": "10.0"
    }
    print("REQ___DATA____________",device_data)
    result = enroll_device(email_address)
    return jsonify(result)
    
    
    # print("REQ___DATA____________",request.json)
    # device_id = request.json.get("device_id")
    # if not device_id:
    #     return jsonify({"error": "Device ID is required"}), 400
    # result = enroll_device(device_id)
    # return jsonify(result)

@app.route('/devices', methods=['GET'])
def devices():
    result = list_devices()
    return jsonify(result)

@app.route('/status', methods=['GET'])
def status():
    return jsonify({"status": "MDM server running"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
