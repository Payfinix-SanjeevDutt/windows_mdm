from flask import Flask, request, jsonify, render_template, Response
import base64
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

# Function to parse SOAP message
def parse_soap_message(decoded_body):
    # Parse the decoded SOAP XML
    tree = ET.ElementTree(ET.fromstring(decoded_body))
    root = tree.getroot()
    
    # Extract data (adjust based on the exact structure of the XML)
    for elem in root.iter():
        print("Roottttttttttttttttt", f"{elem.tag}: {elem.text}")
        print("\n")
    return root

# Compliance Status
@app.route('/EnrollmentServer/Compliance.svc', methods=['GET'])
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


@app.route('/EnrollmentServer/Discovery.svc', methods=['POST'])
def discovery_service():
    try:
        print("Raw Request Body:", request.data)
        print("Content-Type:", request.content_type)

        decoded_body = request.data.decode('utf-8')
        print("Decoded BODY:", decoded_body)

        root = ET.fromstring(decoded_body)
        for elem in root.iter():
            print(f"{elem.tag}: {elem.text}")

        soap_response = """<?xml version="1.0" encoding="utf-8"?>
        <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:w="http://schemas.microsoft.com/windows/management/2012/01/enrollment">
            <s:Body>
                <w:DiscoveryResponse>
                    <w:AuthPolicy>Federated</w:AuthPolicy>
                    <w:EnrollmentVersion>5.0</w:EnrollmentVersion>
                    <w:EnrollmentPolicyServiceUrl>https://windowsmdm.sujanix.com/EnrollmentServer/Policy.svc</w:EnrollmentPolicyServiceUrl>
                    <w:EnrollmentServiceUrl>https://windowsmdm.sujanix.com/EnrollmentServer/Enroll.svc</w:EnrollmentServiceUrl>
                    <w:TermsOfUseUrl>https://windowsmdm.sujanix.com/terms-of-use</w:TermsOfUseUrl>
                    <w:ComplianceServiceUrl>https://windowsmdm.sujanix.com/EnrollmentServer/Compliance.svc</w:ComplianceServiceUrl>
                </w:DiscoveryResponse>
            </s:Body>
        </s:Envelope>"""
        print("soap_response...", soap_response)
        return Response(soap_response, content_type="application/soap+xml")

    except Exception as e:
        print("Error processing request:", e)
        return "Error processing SOAP request", 500

    # return "Invalid Request", 400


@app.route('/EnrollmentServer/Enroll.svc', methods=['POST'])
def enroll_service():
    # Check if the request content type is SOAP
    if request.content_type == "application/soap+xml":
        try:
            # Log the request body for debugging
            app.logger.info(f"Incoming SOAP Request: {request.data.decode('utf-8')}")

            # Parse and process the SOAP request here (use `xml.etree.ElementTree` or a SOAP library like `zeep` if needed)
            soap_request = request.data.decode("utf-8")

            # Example of extracting a device identifier (e.g., EmailAddress, DeviceType)
            # You'll need to replace this with proper XML parsing
            device_id = "12345100-DEVICE-ID"  # Replace with extracted or generated device ID

            # Construct the SOAP response
            soap_response = f"""<?xml version="1.0" encoding="utf-8"?>
            <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
                <s:Body>
                    <EnrollResponse xmlns="http://schemas.microsoft.com/windows/management/2012/01/enrollment">
                        <AuthPolicy>Federated</AuthPolicy>
                        <EnrollmentVersion>5.0</EnrollmentVersion>
                        <EnrollStatus>Success</EnrollStatus>
                        <DeviceIdentifier>{device_id}</DeviceIdentifier>
                        <ServerInfo>
                            <EnrollServiceUrl>https://windowsmdm.sujanix.com/EnrollmentServer/Enroll.svc</EnrollServiceUrl>
                            <PolicyServiceUrl>https://windowsmdm.sujanix.com/EnrollmentServer/Policy.svc</PolicyServiceUrl>
                        </ServerInfo>
                    </EnrollResponse>
                </s:Body>
            </s:Envelope>"""

            return Response(soap_response, content_type="application/soap+xml")
        except Exception as e:
            # Handle errors and log them
            app.logger.error(f"Error processing SOAP request: {str(e)}")
            error_response = f"""<?xml version="1.0" encoding="utf-8"?>
            <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
                <s:Body>
                    <s:Fault>
                        <faultcode>s:Client</faultcode>
                        <faultstring>Invalid Request</faultstring>
                    </s:Fault>
                </s:Body>
            </s:Envelope>"""
            return Response(error_response, content_type="application/soap+xml", status=500)
    else:
        return "Invalid Request: Content type must be application/soap+xml", 400
    
    
@app.route('/EnrollmentServer/Policy.svc', methods=['POST'])
def policy_service():
    # Check if the request content type is SOAP
    if request.content_type == "application/soap+xml":
        try:
            # Log the request body for debugging
            app.logger.info(f"Incoming SOAP Request: {request.data.decode('utf-8')}")

            # Parse and process the SOAP request here (use `xml.etree.ElementTree` or a SOAP library)
            soap_request = request.data.decode("utf-8")

            # Example: Extract device ID or policy request details from the SOAP request
            # Replace this with actual XML parsing logic
            device_id = "12345100-DEVICE-ID"  # Replace with extracted device ID from the request

            # Construct the SOAP response with policies
            # You can dynamically populate policies based on the device or user identity
            soap_response = f"""<?xml version="1.0" encoding="utf-8"?>
            <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
                <s:Body>
                    <GetPoliciesResponse xmlns="http://schemas.microsoft.com/windows/management/2012/01/policy">
                        <Policies>
                            <Policy>
                                <PolicyId>ExamplePolicy</PolicyId>
                                <PolicyType>DeviceRestriction</PolicyType>
                                <PolicyVersion>1.0</PolicyVersion>
                                <PolicyData>
                                    <Restrictions>
                                        <AllowCamera>false</AllowCamera>
                                        <AllowBluetooth>true</AllowBluetooth>
                                    </Restrictions>
                                </PolicyData>
                            </Policy>
                            <Policy>
                                <PolicyId>PasswordPolicy</PolicyId>
                                <PolicyType>Password</PolicyType>
                                <PolicyVersion>2.0</PolicyVersion>
                                <PolicyData>
                                    <PasswordComplexity>High</PasswordComplexity>
                                    <MinimumLength>8</MinimumLength>
                                    <RequireSpecialCharacters>true</RequireSpecialCharacters>
                                </PolicyData>
                            </Policy>
                        </Policies>
                    </GetPoliciesResponse>
                </s:Body>
            </s:Envelope>"""

            return Response(soap_response, content_type="application/soap+xml")

        except Exception as e:
            # Handle errors and log them
            app.logger.error(f"Error processing SOAP request: {str(e)}")
            error_response = f"""<?xml version="1.0" encoding="utf-8"?>
            <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
                <s:Body>
                    <s:Fault>
                        <faultcode>s:Client</faultcode>
                        <faultstring>Invalid Request</faultstring>
                    </s:Fault>
                </s:Body>
            </s:Envelope>"""
            return Response(error_response, content_type="application/soap+xml", status=500)
    else:
        return "Invalid Request: Content type must be application/soap+xml", 400


# MDM Discovery (Optional for Azure testing)
# @app.route('/discover', methods=['GET'])
# def mdm_discovery():
#     print("HI")    
#     return jsonify({
#         "service_url": "https://windowsmdm.sujanix.com",
#         "terms_of_use_url": "https://windowsmdm.sujanix.com/terms-of-use",
#         "compliance_url": "https://windowsmdm.sujanix.com/compliance",
#          "enrollment_url": "https://windowsmdm.sujanix.com/enroll"
#     })

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
