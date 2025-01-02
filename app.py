from flask import Flask, request, jsonify, render_template, Response, make_response
import base64
import re
from utils.graph_api import enroll_device, list_devices
import xml.etree.ElementTree as ET
import requests
from xml.etree.ElementTree import Element

from blueprint import mdm_blueprint


app = Flask(__name__)

@app.route("/")
def home():
    return jsonify({
        "message": "Welcome to theWindows MDM Server",
        "endpoints": {
            "discovery": "https://windowsmdm.sujanix.com/EnrollmentServer/Discovery.svc",
            "terms_of_use": "https://windowsmdm.sujanix.com/EnrollmentServer/terms-of-use",
            "compliance": "https://windowsmdm.sujanix.comEnrollmentServer/Compliance.svc",
            "enrollment" : "https://windowsmdm.sujanix.com/EnrollmentServer/Enrollment.svc"
        },
       
    })
    
    
@app.route('/callback', methods=['POST'])
def callback_handler():
    # Extract the hidden field 'wresult' from the POST request
    wresult = request.form.get('wresult')

    # Validate the token (you can add custom logic here)
    if wresult == "TODOSpecialTokenWhichVerifiesAuth":
        # Successful validation
        response_message = "Authentication Successful"
        status_code = 200
    else:
        # Invalid token
        response_message = "Authentication Failed"
        status_code = 401

    # Return response
    return Response(response_message, status=status_code, content_type="text/plain")


# Serve the Terms of Use
@app.route('/EnrollmentServer/TermsofUse', methods=['GET'])
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


@app.route('/EnrollmentServer/Discovery.svc',methods=['GET', 'POST'])
# def discovery_service():
#     print(f"Discovery API Hit: {request.method} from {request.remote_addr}")
#     return jsonify({
#         "ServiceUrl": "https://windowsmdm.sujanix.com/EnrollmentServer/Enrollment.svc"
#     })
def discovery_service():
    # try:
    #     print("Raw Request Body:", request.data)
    #     print("Content-Type:", request.content_type)

    #     decoded_body = request.data.decode('utf-8')
    #     print("Decoded BODY:", decoded_body)

    #     root = ET.fromstring(decoded_body)
    #     for elem in root.iter():
    #         print(f"{elem.tag}: {elem.text}")

    #     soap_response = """<?xml version="1.0" encoding="utf-8"?>
    #     <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:w="http://schemas.microsoft.com/windows/management/2012/01/enrollment">
    #         <s:Body>
    #             <w:DiscoveryResponse>
    #                 <w:AuthPolicy>Federated</w:AuthPolicy>
    #                 <w:EnrollmentVersion>5.0</w:EnrollmentVersion>
    #                 <w:EnrollmentPolicyServiceUrl>https://windowsmdm.sujanix.com/EnrollmentServer/Policy.svc</w:EnrollmentPolicyServiceUrl>
    #                 <w:EnrollmentServiceUrl>https://windowsmdm.sujanix.com/EnrollmentServer/Enrollment.svc</w:EnrollmentServiceUrl>
    #                 <w:TermsOfUseUrl>https://windowsmdm.sujanix.com/terms-of-use</w:TermsOfUseUrl>
    #                 <w:ComplianceServiceUrl>https://windowsmdm.sujanix.com/EnrollmentServer/Compliance.svc</w:ComplianceServiceUrl>
    #             </w:DiscoveryResponse>
    #         </s:Body>
    #     </s:Envelope>"""
    #     print("soap_response...", soap_response)
    #     return Response(soap_response, content_type="application/soap+xml")
    
    # Global variables for authentication policy and domain
    auth_policy = "Federated"  # Update as needed
    domain = "windowsmdm.sujanix.com"  # Replace with your domain
    if request.method == 'GET':
        # Return HTTP Status 200 OK for GET requests
        return Response(status=200)

    try:
        # Read the HTTP request body
        body = request.data.decode('utf-8')

        # Extract the MessageID from the request body
        message_id_match = re.search(r'<a:MessageID>(.*?)<\/a:MessageID>', body)
        if not message_id_match:
            return Response("Invalid Request: MessageID not found", status=400)
        message_id = message_id_match.group(1)

        # Prepare additional parameters based on the auth policy
        extra_params = ""
        if auth_policy == "Federated":
            extra_params = f"<AuthenticationServiceUrl>https://{domain}/EnrollmentServer/Auth</AuthenticationServiceUrl>"

        # Create the response payload
        response_payload = f"""<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
                        <s:Header>
                            <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/management/2012/01/enrollment/IDiscoveryService/DiscoverResponse</a:Action>
                            <ActivityId CorrelationId="8c6060c4-3d78-4d73-ae17-e8bce88426ee" xmlns="http://schemas.microsoft.com/2004/09/ServiceModel/Diagnostics">8c6060c4-3d78-4d73-ae17-e8bce88426ee</ActivityId>
                            <a:RelatesTo>{message_id}</a:RelatesTo>
                        </s:Header>
                        <s:Body>
                            <DiscoverResponse xmlns="http://schemas.microsoft.com/windows/management/2012/01/enrollment">
                                <DiscoverResult>
                                    <AuthPolicy>{auth_policy}</AuthPolicy>
                                    <EnrollmentVersion>4.0</EnrollmentVersion>
                                    <EnrollmentPolicyServiceUrl>https://{domain}/EnrollmentServer/Policies.svc</EnrollmentPolicyServiceUrl>
                                    <EnrollmentServiceUrl>https://{domain}/EnrollmentServer/Enrollment.svc</EnrollmentServiceUrl>
                                    {extra_params}
                                </DiscoverResult>
                            </DiscoverResponse>
                        </s:Body>
                        </s:Envelope>"""

        # Return the response
        return Response(response_payload, status=200, content_type="application/soap+xml; charset=utf-8")

    except Exception as e:
        return Response(f"Internal Server Error: {str(e)}", status=500)
    except Exception as e:
        print("Error processing request:", e)
        return "Error processing SOAP request", 500
    
    

@app.route('/EnrollmentServer/Auth', methods=['GET'])
def auth_handler():
    print("________AUTH_______________")
    # Extract the 'appru' query parameter
    appru = request.args.get('appru', '#')  # Default to '#' if 'appru' is missing
    print("appru>>>>>>>>>>>>>>>>", appru)

    # Construct the HTML response
    html_content = f"""
    <h3>MDM Federated Login</h3>
    <form method="post" action="{appru}">
        <p><input type="hidden" name="wresult" value="TODOSpecialTokenWhichVerifiesAuth"/></p>
        <input type="submit" value="Login" />
    </form>
    """
    # Return the HTML response
    return Response(html_content, content_type="text/html; charset=UTF-8")

    
    
    
@app.route('/EnrollmentServer/Enrollment.svc', methods=['POST'])
def enroll_service():
    print(f"Enrollment API Hit:::: {request.method} from {request.remote_addr}")
    # Check if the request content type is SOAP
    # if request.content_type == "application/soap+xml":
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
                <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                            xmlns:w="http://schemas.microsoft.com/windows/management/2012/01/enrollment">
                    <s:Body>
                        <w:EnrollmentResponse>
                            <w:ResponseStatus>Success</w:ResponseStatus>
                            
                        </w:EnrollmentResponse>
                    </s:Body>
                </s:Envelope>"""
    
            # soap_response = f"""<?xml version="1.0" encoding="utf-8"?>
            # <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
            #     <s:Body>
            #         <EnrollResponse xmlns="http://schemas.microsoft.com/windows/management/2012/01/enrollment">
            #             <AuthPolicy>Federated</AuthPolicy>
            #             <EnrollmentVersion>5.0</EnrollmentVersion>
            #             <EnrollStatus>Success</EnrollStatus>
            #             <DeviceIdentifier>{device_id}</DeviceIdentifier>
            #             <ServerInfo>
            #                 <EnrollServiceUrl>https://windowsmdm.sujanix.com/EnrollmentServer/Enroll.svc</EnrollServiceUrl>
            #                 <PolicyServiceUrl>https://windowsmdm.sujanix.com/EnrollmentServer/Policy.svc</PolicyServiceUrl>
            #             </ServerInfo>
            #         </EnrollResponse>
            #     </s:Body>
            # </s:Envelope>"""
            
            response = make_response(soap_response)
            response.headers['Content-Type'] = 'application/soap+xml; charset=utf-8'
            print("ENT_RES_______", response)
            return response
        
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

    
    
# @app.route('/EnrollmentServer/Policy.svc', methods=['POST'])
# def policy_service():
#     if request.content_type == "application/soap+xml":
#         try:
#             app.logger.info(f"Incoming SOAP Request: {request.data.decode('utf-8')}")
#             soap_request = request.data.decode("utf-8")

#             device_id = "12345100-DEVICE-ID" 

#             soap_response = f"""<?xml version="1.0" encoding="utf-8"?>
#             <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
#                 <s:Body>
#                     <GetPoliciesResponse xmlns="http://schemas.microsoft.com/windows/management/2012/01/policy">
#                         <Policies>
#                             <Policy>
#                                 <PolicyId>ExamplePolicy</PolicyId>
#                                 <PolicyType>DeviceRestriction</PolicyType>
#                                 <PolicyVersion>1.0</PolicyVersion>
#                                 <PolicyData>
#                                     <Restrictions>
#                                         <AllowCamera>false</AllowCamera>
#                                         <AllowBluetooth>true</AllowBluetooth>
#                                     </Restrictions>
#                                 </PolicyData>
#                             </Policy>
#                             <Policy>
#                                 <PolicyId>PasswordPolicy</PolicyId>
#                                 <PolicyType>Password</PolicyType>
#                                 <PolicyVersion>2.0</PolicyVersion>
#                                 <PolicyData>
#                                     <PasswordComplexity>High</PasswordComplexity>
#                                     <MinimumLength>8</MinimumLength>
#                                     <RequireSpecialCharacters>true</RequireSpecialCharacters>
#                                 </PolicyData>
#                             </Policy>
#                         </Policies>
#                     </GetPoliciesResponse>
#                 </s:Body>
#             </s:Envelope>"""

#             return Response(soap_response, content_type="application/soap+xml")

#         except Exception as e:
           
#             app.logger.error(f"Error processing SOAP request: {str(e)}")
#             error_response = f"""<?xml version="1.0" encoding="utf-8"?>
#             <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
#                 <s:Body>
#                     <s:Fault>
#                         <faultcode>s:Client</faultcode>
#                         <faultstring>Invalid Request</faultstring>
#                     </s:Fault>
#                 </s:Body>
#             </s:Envelope>"""
#             return Response(error_response, content_type="application/soap+xml", status=500)
#     else:
#         return "Invalid Request: Content type must be application/soap+xml", 400
@app.route('/EnrollmentServer/Policies.svc', methods=['GET'])
def get_policies():
    # Example policies in XML format
    policies = """<?xml version="1.0" encoding="utf-8"?>
    <Policies>
        <Policy>
            <WiFi>
                <SSID>vivo T3 Ultra</SSID>
                <Password>suchet123</Password>
            </WiFi>
            <Compliance>
                <PasswordRequired>True</PasswordRequired>
                <EncryptionRequired>True</EncryptionRequired>
            </Compliance>
        </Policy>
    </Policies>"""

    response = make_response(policies)
    response.headers['Content-Type'] = 'application/xml; charset=utf-8'
    return response


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

# @app.route('/devices', methods=['GET'])
# def devices():
#     result = list_devices()
#     return jsonify(result)

@app.route('/status', methods=['GET'])
def status():
    return jsonify({"status": "MDM server running"})






















if __name__ == "__main__":
    app.register_blueprint(mdm_blueprint)
    app.run(host="0.0.0.0", port=5000)
