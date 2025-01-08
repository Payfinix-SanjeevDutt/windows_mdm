from flask import Flask, request, jsonify, render_template, Response, make_response, redirect, render_template_string
from xml.etree.ElementTree import Element, SubElement, tostring, fromstring
from utils.graph_api import *
import uuid
import base64
from jose import jwt, jwk
import requests
import re
from utils.graph_api import enroll_device, list_devices, list_all_devcies
import xml.etree.ElementTree as ET
import requests
from xml.etree.ElementTree import Element
from config import Config

app = Flask(__name__)

@app.route("/")
def home():
    return jsonify({
        "message": "Welcome to theWindows MDM Server",
        "endpoints": {
            "discovery": "https://windowsmdm.sujanix.com/EnrollmentServer/Discovery.svc",
            "terms_of_use": "https://windowsmdm.sujanix.com/EnrollmentServer/TermsofUse",
            "compliance": "https://windowsmdm.sujanix.comEnrollmentServer/Compliance.svc",
            "enrollment": "https://windowsmdm.sujanix.com/EnrollmentServer/Enrollment.svc"
        },

    })

@app.route('/EnrollmentServer/TermsofUse', methods=['GET'])
def terms_of_use():
    return render_template('terms_of_use.html')


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


@app.route('/EnrollmentServer/Discovery.svc', methods=['GET', 'POST'])
def discovery_service():
    print(f"Discovery API Hit: {request.method} from {request.remote_addr}")
    if request.method == 'GET':
        return Response(status=200 , message="https://windowsmdm.sujanix.com/EnrollmentServer/Enrollment.svc")
    try:
        print("_____________POST___________________")
        # Parse the incoming request XML
        request_xml = fromstring(request.data)
        body = request.data.decode('utf-8')
        print("request.data", body)
          # Extract the MessageID from the request body
        message_id_match = re.search(r'<a:MessageID>(.*?)<\/a:MessageID>', body)
        if not message_id_match:
            return Response("Invalid Request: MessageID not found", status=400)
        message_id = message_id_match.group(1)
 
        email_match = re.search(r'<EmailAddress>(.*?)<\/EmailAddress>', body)
        email_address = email_match.group(1) if email_match else "Not Provided"
 
        os_edition_match = re.search(r'<OSEdition>(.*?)<\/OSEdition>', body)
        os_edition = os_edition_match.group(1) if os_edition_match else "Not Provided"
 
        device_type_match = re.search(r'<DeviceType>(.*?)<\/DeviceType>', body)
        device_type = device_type_match.group(1) if device_type_match else "Not Provided"
 
        app_version_match = re.search(r'<ApplicationVersion>(.*?)<\/ApplicationVersion>', body)
        application_version = app_version_match.group(1) if app_version_match else "Not Provided"

        print(f"1MessageID: {message_id}")
        print(f"1Email Address: {email_address}")
        print(f"1OS Edition: {os_edition}")
        print(f"1Device Type: {device_type}")
        print(f"1Application Version: {application_version}")
        
        email_address = email_address
        os_edition = os_edition
        device_type =device_type
        application_version =application_version
        message_id_text = message_id
        print("message_id_text", message_id_text)

        auth_policy = "Federated"  
        domain = "windowsmdm.sujanix.com" 
        activity_id = str(uuid.uuid4())
        print("activity_id---", activity_id)
    
        response_payload = f"""<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://www.w3.org/2005/08/addressing">
            <s:Header>
                <a:Action s:mustUnderstand="1">
                    http://schemas.microsoft.com/windows/management/2012/01/enrollment/IDiscoveryService/DiscoverResponse
                </a:Action>
                <ActivityId>
                   {activity_id}
                </ActivityId>
                <a:RelatesTo>{message_id_text}</a:RelatesTo>
            </s:Header>
            <s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                xmlns:xsd="http://www.w3.org/2001/XMLSchema">
                <DiscoverResponse xmlns="http://schemas.microsoft.com/windows/management/2012/01/enrollment">
                    <DiscoverResult>
                        <AuthPolicy>Federated</AuthPolicy>
                        <EnrollmentVersion>3.0</EnrollmentVersion>
                        <AuthenticationServiceUrl>
                            https://{domain}/AuthenticationService.svc
                        </AuthenticationServiceUrl>
                        <EnrollmentServiceUrl>
                            https://{domain}/EnrollmentServer/Enrollment.svc
                        </EnrollmentServiceUrl>
                        <EnrollmentPolicyServiceUrl>
                           https://{domain}/EnrollmentServer/Policies.svc
                        </EnrollmentPolicyServiceUrl>

                    </DiscoverResult>
                </DiscoverResponse>
            </s:Body>
            </s:Envelope>"""
        print("response_payload------------", response_payload)
    
        return Response(response_payload, content_type='application/soap+xml')
    except Exception as e:
        return Response(f"Internal Server Error: {str(e)}", status=500)


@app.route('/AuthenticationService.svc', methods=['GET', 'POST'])
def authentication_service():
    if request.method == 'GET':

        tenant_id = Config.TENANT_ID
        client_id = Config.CLIENT_ID
        redirect_uri = "https://windowsmdm.sujanix.com/auth/callback"
        authority = f"https://login.microsoftonline.com/{tenant_id}"
        auth_url = f"{authority}/oauth2/v2.0/authorize"
 
        # Query parameters for Azure AD
        auth_params = {
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "response_mode": "query",
            "scope": "openid profile email",
            # "appru": f"ms-app://{client_id}",
            "state": "state_value",  # Optional: CSRF protection
        }
    
        # Redirect to Azure AD login page
        query_string = "&".join(f"{key}={value}" for key, value in auth_params.items())
        print("query_string==", query_string)
        return redirect(f"{auth_url}?{query_string}")
    


@app.route('/auth/callback', methods=['GET'])
def auth_callback():
    print("_____CALLLBACKKKKKKK_____________",request.args)
    tenant_id = Config.TENANT_ID
    client_id = Config.CLIENT_ID
    client_secret = Config.CLIENT_SECRET
    redirect_uri = "https://windowsmdm.sujanix.com/auth/callback"
    token_endpoint = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
 
    # Extract query parameters
    code = request.args.get('code')
    # appru = request.args.get('appru',f"ms-app://{client_id}" )
    
    if not code:
        return "Authorization code missing", 400
 
    # Exchange the authorization code for an access token
    token_payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
        # "appru": f"ms-app://{client_id}",
    }
    token_response = requests.post(token_endpoint, data=token_payload)
 
    if token_response.status_code == 200:
        token_data = token_response.json()
        access_token = token_data.get("access_token")
        print("access_token>>>>>>>>>>>", access_token)
        print("_____WAB______PAGE_________")
        # Return the WAB end page with the token
        return render_template_string("""
                <!DOCTYPE html>
                <html>
                <head>
                <title>Authentication Complete</title>
                <script>
                    function formSubmit() {
                        document.forms[0].submit();
                    }
                    window.onload = formSubmit;
                </script>
                </head>
                <body>
                <form method="post" action="ms-app://windows.immersivecontrolpanel">
                <p><input type="hidden" name="wresult" value="{{access_token}}" /></p>
                <input type="submit" />
                </form>
                </body>
                </html>
        """, client_id=client_id, access_token=access_token)
 
    return f"Error fetching token: {token_response.text}", 500


@app.route('/EnrollmentServer/Enrollment.svc', methods=['POST'])
def enroll_service():
    print("____________________ENROLLLL____________________________")
    try:
        soap_request = request.data.decode("utf-8")

        token_match = re.search(r'<wresult>(.*?)<\/wresult>', soap_request)
        if not token_match:
            return Response("Invalid Request: Token not found", status=400)
        token = token_match.group(1)

        # Validate the token using Azure AD
        tenant_id = Config.TENANT_ID
        client_id = Config.CLIENT_ID
        jwks_uri = f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
        keys = requests.get(jwks_uri).json().get("keys", [])

        # Decode and validate the token
        header = jwt.get_unverified_header(token)
        key = next(k for k in keys if k["kid"] == header["kid"])
        decoded_token = jwt.decode(
            token,
            jwk.construct(key),
            audience=client_id,
            issuer=f"https://login.microsoftonline.com/{tenant_id}/v2.0",
            options={"verify_exp": True},
        )

        print("Decoded Token:", decoded_token)

        # Proceed with enrollment if token is valid
        soap_response = """<?xml version="1.0" encoding="utf-8"?>
            <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.microsoft.com/windows/management/2012/01/enrollment">
                <s:Body>
                    <w:EnrollmentResponse>
                        <w:ResponseStatus>Success</w:ResponseStatus>
                    </w:EnrollmentResponse>
                </s:Body>
            </s:Envelope>"""

        return Response(soap_response, status=200, content_type="application/soap+xml; charset=utf-8")

    except Exception as e:
        print(f"Error processing enrollment: {str(e)}")
        error_response = """<?xml version="1.0" encoding="utf-8"?>
            <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
                <s:Body>
                    <s:Fault>
                        <faultcode>s:Client</faultcode>
                        <faultstring>Invalid Token</faultstring>
                    </s:Fault>
                </s:Body>
            </s:Envelope>"""
        return Response(error_response, status=400, content_type="application/soap+xml")


@app.route('/EnrollmentServer/Policies.svc', methods=['GET','POST'])
def get_policies():
    print("__POLICIES__________________", request.method)
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

@app.route('/devices', methods=['GET'])
def devices():
    result = list_devices()
    return jsonify(result)


@app.route('/status', methods=['GET'])
def status():
    return jsonify({"status": "MDM server running"})

@app.route('/all-devices', methods=['GET'])
def all_devices():
    result = list_all_devcies()
    return jsonify(result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
