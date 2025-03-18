from flask import Flask, request, jsonify, render_template, Response, redirect, render_template_string
from jose import jwt, JOSEError
import hashlib
from xml.etree.ElementTree import Element, SubElement, tostring, fromstring
from lxml import etree
from xml.etree.ElementTree import fromstring
from datetime import datetime, timezone, timedelta
import uuid
import base64
import re
import requests
import xml.etree.ElementTree as ET
from config import Config
from OpenSSL import crypto
import json

app = Flask(__name__)

@app.route("/")

def read_certificate(cert_path, key_path):
    with open(cert_path, "rb") as cert_file:
        cert = cert_file.read()
    with open(key_path, "rb") as key_file:
        key = key_file.read()
    return cert, key
 
 
def create_signed_certificate(csr_raw, root_cert, root_key, device_id):
    # Parse the CSR (assumed to be in DER format)
    csr = crypto.load_certificate_request(crypto.FILETYPE_ASN1, csr_raw)
    # Create a new certificate
    cert = crypto.X509()
    cert.set_serial_number(int(uuid.uuid4().int >> 64))  # Random serial number
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # 1 year validity
    cert.set_issuer(root_cert.get_subject())
    cert.set_subject(csr.get_subject())
    cert.set_pubkey(csr.get_pubkey())
    cert.sign(root_key, "sha256")
    return crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)

def home():
    return jsonify({
        "message": "Welcome to the Windows MDM Server",
        "endpoints": {
            "discovery": "https://windowsmdm.sujanix.com/EnrollmentServer/Discovery.svc",
            "terms_of_use": "https://windowsmdm.sujanix.com/EnrollmentServer/TermsofUse",
            "compliance": "https://windowsmdm.sujanix.com/EnrollmentServer/Compliance.svc",
            "enrollment": "https://windowsmdm.sujanix.com/EnrollmentServer/Enrollment.svc"
        },
    })
    

@app.route('/EnrollmentServer/TermsofUse', methods=['GET'])
def terms_of_use():
    return render_template('terms_of_use.html')

@app.route('/EnrollmentServer/Discovery.svc', methods=['GET', 'POST'])
def discovery_service():
    print(f"Discovery API Hit: {request.method} from {request.remote_addr}")
    if request.method == 'GET':
        # For GET requests, simply return the enrollment service URL.
        return Response("https://windowsmdm.sujanix.com/EnrollmentServer/Enrollment.svc", status=200)

    try:
        # Decode and log incoming XML request.
        body = request.data.decode('utf-8')
        print("Discovery Request Data:", body)
        
        # Extract required fields using regex.
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

        print(f"MessageID: {message_id}")
        print(f"Email Address: {email_address}")
        print(f"OS Edition: {os_edition}")
        print(f"Device Type: {device_type}")
        print(f"Application Version: {application_version}")

        # For federated authentication, set AuthPolicy and build the response.
        auth_policy = "Federated"
        domain = "windowsmdm.sujanix.com"
        activity_id = str(uuid.uuid4())
        print("Generated Activity ID:", activity_id)

        response_payload = f"""<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://www.w3.org/2005/08/addressing">
        <s:Header>
            <a:Action s:mustUnderstand="1">
            http://schemas.microsoft.com/windows/management/2012/01/enrollment/IDiscoveryService/DiscoverResponse
            </a:Action>
            <ActivityId>{activity_id}</ActivityId>
            <a:RelatesTo>{message_id}</a:RelatesTo>
        </s:Header>
        <s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                xmlns:xsd="http://www.w3.org/2001/XMLSchema">
            <DiscoverResponse xmlns="http://schemas.microsoft.com/windows/management/2012/01/enrollment">
            <DiscoverResult>
                <AuthPolicy>{auth_policy}</AuthPolicy>
                <EnrollmentVersion>3.0</EnrollmentVersion>
                <AuthenticationServiceUrl>https://{domain}/AuthenticationService.svc</AuthenticationServiceUrl>
                <EnrollmentPolicyServiceUrl>https://{domain}/ENROLLMENTSERVER/DEVICEENROLLMENTWEBSERVICE.SVC</EnrollmentPolicyServiceUrl>
                <EnrollmentServiceUrl>https://{domain}/EnrollmentServer/Enrollment.svc</EnrollmentServiceUrl>
            </DiscoverResult>
            </DiscoverResponse>
        </s:Body>
        </s:Envelope>"""
        print("Discovery Response Payload:", response_payload)
        return Response(response_payload, content_type='application/soap+xml')
    except Exception as e:
        return Response(f"Internal Server Error: {str(e)}", status=500)

@app.route('/AuthenticationService.svc', methods=['GET', 'POST'])
def authentication_service():
    if request.method == 'GET':
        # Redirect the device to Microsoft Entra ID (Azure AD) for federated authentication.
        tenant_id = Config.TENANT_ID
        client_id = Config.CLIENT_ID
        redirect_uri = "https://windowsmdm.sujanix.com/auth/callback"
        authority = f"https://login.microsoftonline.com/{tenant_id}"
        auth_url = f"{authority}/oauth2/v2.0/authorize"

        auth_params = {
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "response_mode": "query",
            "scope": "openid profile email",
            "state": "state_value",  
        }
        query_string = "&".join(f"{key}={value}" for key, value in auth_params.items())
        print("Authentication Query String:", query_string)
        return redirect(f"{auth_url}?{query_string}")
    else:
        # For POST requests, you might add additional handling if needed.
        return Response("POST not implemented on AuthenticationService", status=405)

@app.route('/auth/callback', methods=['GET'])
def auth_callback():
    print("Auth Callback received with args:", request.args)
    tenant_id = Config.TENANT_ID
    client_id = Config.CLIENT_ID
    client_secret = Config.CLIENT_SECRET
    redirect_uri = "https://windowsmdm.sujanix.com/auth/callback"
    token_endpoint = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

    code = request.args.get('code')
    if not code:
        return "Authorization code missing", 400

    token_payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }
    token_response = requests.post(token_endpoint, data=token_payload)

    if token_response.status_code == 200:
        token_data = token_response.json()
        access_token = token_data.get("access_token")
        print("Access Token:", access_token)
        # Render the Web Authentication Broker (WAB) end page that posts the token.
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
                <input type="hidden" name="wresult" value="{{ access_token }}" />
                <input type="submit" />
              </form>
            </body>
            </html>
        """, access_token=access_token)
    return f"Error fetching token: {token_response.text}", 500

@app.route('/ENROLLMENTSERVER/DEVICEENROLLMENTWEBSERVICE.SVC', methods=['POST'])
def enrollment_policy_service():
    body_raw = request.data
    body = body_raw.decode('utf-8')
    print("Enrollment Policy Request Body:", body)
    message_id_match = re.search(r'<a:MessageID>(.*?)<\/a:MessageID>', body)
    if message_id_match:
        message_id = message_id_match.group(1)
    else:
        return Response("Invalid request: MessageID not found", status=400)
    print("Enrollment Policy MessageID:", message_id)

    response_payload = f"""<s:Envelope
    xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
    xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://www.w3.org/2005/08/addressing">
  <s:Header>
    <a:Action s:mustUnderstand="1">
      http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPoliciesResponse
    </a:Action>
    <a:RelatesTo>{message_id}</a:RelatesTo>
  </s:Header>
  <s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <GetPoliciesResponse xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy">
      <response>
        <policyID />
        <policyFriendlyName xsi:nil="true" />
        <nextUpdateHours xsi:nil="true" />
        <policiesNotChanged xsi:nil="true" />
        <policies>
          <policy>
            <policyOIDReference>0</policyOIDReference>
            <cAs xsi:nil="true" />
            <attributes>
              <commonName>CEPUnitTest</commonName>
              <policySchema>3</policySchema>
              <certificateValidity>
                <validityPeriodSeconds>1209600</validityPeriodSeconds>
                <renewalPeriodSeconds>172800</renewalPeriodSeconds>
              </certificateValidity>
              <permission>
                <enroll>true</enroll>
                <autoEnroll>false</autoEnroll>
              </permission>
              <privateKeyAttributes>
                <minimalKeyLength>2048</minimalKeyLength>
                <keySpec xsi:nil="true" />
                <keyUsageProperty xsi:nil="true" />
                <permissions xsi:nil="true" />
                <algorithmOIDReference xsi:nil="true" />
                <cryptoProviders xsi:nil="true" />
              </privateKeyAttributes>
              <revision>
                <majorRevision>101</majorRevision>
                <minorRevision>0</minorRevision>
              </revision>
              <supersededPolicies xsi:nil="true" />
              <privateKeyFlags xsi:nil="true" />
              <subjectNameFlags xsi:nil="true" />
              <enrollmentFlags xsi:nil="true" />
              <generalFlags xsi:nil="true" />
              <hashAlgorithmOIDReference>0</hashAlgorithmOIDReference>
              <rARequirements xsi:nil="true" />
              <keyArchivalAttributes xsi:nil="true" />
              <extensions xsi:nil="true" />
            </attributes>
          </policy>
        </policies>
      </response>
      <cAs xsi:nil="true" />
      <oIDs>
        <oID>
          <value>1.3.14.3.2.29</value>
          <group>1</group>
          <oIDReferenceID>0</oIDReferenceID>
          <defaultName>szOID_OIWSEC_sha1RSASign</defaultName>
        </oID>
      </oIDs>
    </GetPoliciesResponse>
  </s:Body>
</s:Envelope>"""
    response = Response(response_payload, status=200)
    response.headers['Content-Type'] = 'application/soap+xml; charset=utf-8'
    response.headers['Content-Length'] = str(len(response_payload))
    print("Enrollment Policy Response:", response)
    return response

@app.route('/EnrollmentServer/Enrollment.svc', methods=['POST'])
def enrollment_service():
    try:
        request_xml = request.data.decode('utf-8')
        print("Enrollment Service Request:", request_xml)

        # Extract the PKCS#10 certificate request from the SOAP body.
        cert_req_match = re.search(
            r'<wsse:BinarySecurityToken[^>]*>(.*?)<\/wsse:BinarySecurityToken>',
            request_xml, re.DOTALL)
        if not cert_req_match:
            return Response("Invalid enrollment request: Certificate request not found", status=400)
        cert_request_base64 = cert_req_match.group(1).strip()
        print("Extracted PKCS#10 Request (Base64):", cert_request_base64)
        
        with open("testserver.crt", "rb") as f:
            pem_data = f.read()
            
        # Convert PEM to DER format
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_data)
        der_data = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
        
        # Base64-encode the DER certificate
        cert_der_b64 = base64.b64encode(der_data).decode('utf-8')
        
        print("Dummy Certificate (Base64):", cert_der_b64)

        provisioning_xml = f"""<wap-provisioningdoc version="1.1">
        <characteristic type="CertificateStore">
            <characteristic type="My">
            <characteristic type="User">
                <characteristic type="ProvisionedCert">
                <parm name="EncodedCertificate" value="{cert_der_b64}" />
                </characteristic>
            </characteristic>
            </characteristic>
        </characteristic>
        <characteristic type="DMClient">
            <characteristic type="Provider">
            <parm name="DMServer" value="https://windowsmdm.sujanix.com/EnrollmentServer/Enrollment.svc" />
            </characteristic>
        </characteristic>
        </wap-provisioningdoc>"""
        provisioning_xml_encoded = base64.b64encode(provisioning_xml.encode('utf-8')).decode('utf-8')

        # Extract MessageID from request for correlation.
        message_id_match = re.search(r'<a:MessageID>(.*?)<\/a:MessageID>', request_xml)
        message_id = message_id_match.group(1) if message_id_match else str(uuid.uuid4())

        # Create Timestamp values for the Security header.
        created_time = datetime.now(timezone.utc).isoformat()
        expires_time = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()

        # Build the SOAP response (RSTR) with Security header.
        response_payload = f"""<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
        xmlns:a="http://www.w3.org/2005/08/addressing"
        xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
        xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
        <s:Header>
            <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep</a:Action>
            <a:RelatesTo>{message_id}</a:RelatesTo>
            <o:Security s:mustUnderstand="1">
            <u:Timestamp u:Id="_0">
                <u:Created>{created_time}</u:Created>
                <u:Expires>{expires_time}</u:Expires>
            </u:Timestamp>
            </o:Security>
        </s:Header>
        <s:Body>
            <RequestSecurityTokenResponseCollection xmlns="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
            <RequestSecurityTokenResponse>
                <TokenType>
                http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentToken
                </TokenType>
                <DispositionMessage xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment"/>
                <RequestedSecurityToken>
                <BinarySecurityToken ValueType="http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentProvisionDoc"
                    EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary">
                    {provisioning_xml_encoded}
                </BinarySecurityToken>
                </RequestedSecurityToken>
                <RequestID xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment">0</RequestID>
            </RequestSecurityTokenResponse>
            </RequestSecurityTokenResponseCollection>
        </s:Body>
        </s:Envelope>"""
        response = Response(response_payload, status=200, content_type='application/soap+xml')
        response.headers['Content-Length'] = str(len(response_payload))
        print("Enrollment Service Response Payload:", response_payload)
        return response
    except Exception as e:
        print("Error in Enrollment Service:", str(e))
        return Response(f"Internal Server Error: {str(e)}", status=500)

    
@app.route('/devices', methods=['GET'])
def devices():
    # Simulated device listing. Replace with your graph_api.list_devices() if available.
    result = {"devices": ["Device1", "Device2"]}
    return jsonify(result)

@app.route('/status', methods=['GET'])
def status():
    return jsonify({"status": "MDM server running"})

@app.route('/all-devices', methods=['GET'])
def all_devices():
    # Simulated all devices listing. Replace with your graph_api.list_all_devcies() if available.
    result = {"all_devices": ["Device1", "Device2", "Device3"]}
    return jsonify(result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)



# main.py

# from flask import Flask, request, jsonify, render_template, Response, redirect, render_template_string, make_response
# from lxml import etree
# from jose import jwt, JOSEError
# from xml.etree.ElementTree import Element, SubElement, tostring, fromstring
# import uuid
# import base64
# import requests
# import re
# import hashlib
# import json
# import OpenSSL.crypto as crypto
# from config import Config
# from utils.graph_api import enroll_device, list_devices, list_all_devcies

# app = Flask(__name__)

# # --------------------------
# # Home and Utility Endpoints
# # --------------------------
# @app.route("/")
# def home():
#     return jsonify({
#         "message": "Welcome to the Windows MDM Server",
#         "endpoints": {
#             "discovery": "https://windowsmdm.sujanix.com/EnrollmentServer/Discovery.svc",
#             "terms_of_use": "https://windowsmdm.sujanix.com/EnrollmentServer/TermsofUse",
#             "compliance": "https://windowsmdm.sujanix.com/EnrollmentServer/Compliance.svc",
#             "enrollment": "https://windowsmdm.sujanix.com/EnrollmentServer/Enrollment.svc",
#             "authentication": "https://windowsmdm.sujanix.com/AuthenticationService.svc"
#         }
#     })

# @app.route('/EnrollmentServer/TermsofUse', methods=['GET'])
# def terms_of_use():
#     return render_template('terms_of_use.html')

# @app.route('/EnrollmentServer/Compliance.svc', methods=['GET'])
# def compliance():
#     device_id = request.args.get("device_id")
#     if not device_id:
#         return jsonify({"error": "Device ID is required"}), 400

#     # Example compliance status (mocked)
#     compliance_status = {
#         "device_id": device_id,
#         "compliant": True,
#         "details": "Device is compliant with all MDM policies."
#     }
#     return jsonify(compliance_status)

# @app.route('/EnrollmentServer/ToS', methods=['GET'])
# def terms_of_service():
#     redirect_uri = request.args.get('redirect_uri', '')
#     client_request_id = request.args.get('client-request-id', '')
#     if not redirect_uri:
#         return "Error: redirect_uri is required", 400
#     html_content = f"""
#     <html>
#     <head>
#       <title>MDM Terms of Use</title>
#     </head>
#     <body>
#       <h3>MDM Terms of Use</h3>
#       <p>Please accept the Terms of Use to proceed with enrollment.</p>
#       <button onclick="window.location.href='{redirect_uri}?IsAccepted=true&OpaqueBlob=someValue&client-request-id={client_request_id}'">Accept</button>
#       <button onclick="window.location.href='{redirect_uri}?IsAccepted=false&client-request-id={client_request_id}'">Decline</button>
#     </body>
#     </html>
#     """
#     response = make_response(html_content)
#     response.headers["Content-Type"] = "text/html; charset=UTF-8"
#     return response

# # --------------------------
# # Discovery Service Endpoint
# # --------------------------
# @app.route('/EnrollmentServer/Discovery.svc', methods=['GET', 'POST'])
# def discovery_service():
#     print(f"Discovery API Hit: {request.method} from {request.remote_addr}")
#     if request.method == 'GET':
#         # For GET requests, simply return the enrollment service URL.
#         return Response("https://windowsmdm.sujanix.com/EnrollmentServer/Enrollment.svc", status=200)

#     try:
#         # Decode and log incoming XML request.
#         body = request.data.decode('utf-8')
#         print("Discovery Request Data:", body)
        
#         # Extract required fields using regex.
#         message_id_match = re.search(r'<a:MessageID>(.*?)<\/a:MessageID>', body)
#         if not message_id_match:
#             return Response("Invalid Request: MessageID not found", status=400)
#         message_id = message_id_match.group(1)

#         email_match = re.search(r'<EmailAddress>(.*?)<\/EmailAddress>', body)
#         email_address = email_match.group(1) if email_match else "Not Provided"

#         os_edition_match = re.search(r'<OSEdition>(.*?)<\/OSEdition>', body)
#         os_edition = os_edition_match.group(1) if os_edition_match else "Not Provided"

#         device_type_match = re.search(r'<DeviceType>(.*?)<\/DeviceType>', body)
#         device_type = device_type_match.group(1) if device_type_match else "Not Provided"

#         app_version_match = re.search(r'<ApplicationVersion>(.*?)<\/ApplicationVersion>', body)
#         application_version = app_version_match.group(1) if app_version_match else "Not Provided"

#         print(f"MessageID: {message_id}")
#         print(f"Email Address: {email_address}")
#         print(f"OS Edition: {os_edition}")
#         print(f"Device Type: {device_type}")
#         print(f"Application Version: {application_version}")

#         # For federated authentication, set AuthPolicy and build the response.
#         auth_policy = "Federated"
#         domain = "windowsmdm.sujanix.com"
#         activity_id = str(uuid.uuid4())
#         print("Generated Activity ID:", activity_id)

#         response_payload = f"""<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
#             xmlns:a="http://www.w3.org/2005/08/addressing">
#         <s:Header>
#             <a:Action s:mustUnderstand="1">
#             http://schemas.microsoft.com/windows/management/2012/01/enrollment/IDiscoveryService/DiscoverResponse
#             </a:Action>
#             <ActivityId>{activity_id}</ActivityId>
#             <a:RelatesTo>{message_id}</a:RelatesTo>
#         </s:Header>
#         <s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
#                 xmlns:xsd="http://www.w3.org/2001/XMLSchema">
#             <DiscoverResponse xmlns="http://schemas.microsoft.com/windows/management/2012/01/enrollment">
#             <DiscoverResult>
#                 <AuthPolicy>{auth_policy}</AuthPolicy>
#                 <EnrollmentVersion>3.0</EnrollmentVersion>
#                 <AuthenticationServiceUrl>https://{domain}/AuthenticationService.svc</AuthenticationServiceUrl>
#                 <EnrollmentPolicyServiceUrl>https://{domain}/ENROLLMENTSERVER/DEVICEENROLLMENTWEBSERVICE.SVC</EnrollmentPolicyServiceUrl>
#                 <EnrollmentServiceUrl>https://{domain}/EnrollmentServer/Enrollment.svc</EnrollmentServiceUrl>
#             </DiscoverResult>
#             </DiscoverResponse>
#         </s:Body>
#         </s:Envelope>"""
#         print("Discovery Response Payload:", response_payload)
#         return Response(response_payload, content_type='application/soap+xml')
#     except Exception as e:
#         return Response(f"Internal Server Error: {str(e)}", status=500)

# @app.route('/AuthenticationService.svc', methods=['GET', 'POST'])
# def authentication_service():
#     if request.method == 'GET':
#         # Redirect the device to Microsoft Entra ID (Azure AD) for federated authentication.
#         tenant_id = Config.TENANT_ID
#         client_id = Config.CLIENT_ID
#         redirect_uri = "https://windowsmdm.sujanix.com/auth/callback"
#         authority = f"https://login.microsoftonline.com/{tenant_id}"
#         auth_url = f"{authority}/oauth2/v2.0/authorize"

#         auth_params = {
#             "client_id": client_id,
#             "response_type": "code",
#             "redirect_uri": redirect_uri,
#             "response_mode": "query",
#             "scope": "openid profile email",
#             "state": "state_value",  
#         }
#         query_string = "&".join(f"{key}={value}" for key, value in auth_params.items())
#         print("Authentication Query String:", query_string)
#         return redirect(f"{auth_url}?{query_string}")
#     else:
#         # For POST requests, you might add additional handling if needed.
#         return Response("POST not implemented on AuthenticationService", status=405)


# # --------------------------
# # Authentication (WAB) Endpoints
# # --------------------------
# @app.route('/AuthenticationService.svc', methods=['GET', 'POST'])
# def authentication_service():
#     if request.method == 'GET':
#         tenant_id = Config.TENANT_ID
#         client_id = Config.CLIENT_ID
#         # Generate a unique state parameter (store in session for production)
#         state = str(uuid.uuid4())
#         redirect_uri = "https://windowsmdm.sujanix.com/auth/callback"
#         authority = f"https://login.microsoftonline.com/{tenant_id}"
#         auth_url = f"{authority}/oauth2/v2.0/authorize"
#         auth_params = {
#             "client_id": client_id,
#             "response_type": "code",
#             "redirect_uri": redirect_uri,
#             "response_mode": "query",
#             "scope": "openid profile email",
#             "state": state,
#         }
#         query_string = "&".join(f"{key}={requests.utils.quote(value)}" for key, value in auth_params.items())
#         print("Auth Query String:", query_string)
#         return redirect(f"{auth_url}?{query_string}")
#     else:
#         return Response("POST not supported on this endpoint", status=405)

# @app.route('/auth/callback', methods=['GET'])
# def auth_callback():
#     print("Callback received with args:", request.args)
#     tenant_id = Config.TENANT_ID
#     client_id = Config.CLIENT_ID
#     client_secret = Config.CLIENT_SECRET
#     redirect_uri = "https://windowsmdm.sujanix.com/auth/callback"
#     token_endpoint = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
#     code = request.args.get('code')
#     if not code:
#         return "Authorization code missing", 400
#     token_payload = {
#         "client_id": client_id,
#         "client_secret": client_secret,
#         "code": code,
#         "grant_type": "authorization_code",
#         "redirect_uri": redirect_uri,
#     }
#     token_response = requests.post(token_endpoint, data=token_payload)
#     if token_response.status_code == 200:
#         token_data = token_response.json()
#         access_token = token_data.get("access_token")
#         print("Access Token:", access_token)
#         # Render the WAB End Page that auto-submits the token back to the enrollment client.
#         wab_end_page = render_template_string("""
#             <!DOCTYPE html>
#             <html>
#             <head>
#               <title>Authentication Complete</title>
#               <script>
#                 function formSubmit() {
#                   document.forms[0].submit();
#                 }
#                 window.onload = formSubmit;
#               </script>
#             </head>
#             <body>
#               <form method="post" action="ms-app://windows.immersivecontrolpanel">
#                 <input type="hidden" name="wresult" value="{{ access_token }}" />
#                 <input type="submit" value="Continue" />
#               </form>
#             </body>
#             </html>
#         """, access_token=access_token)
#         return wab_end_page
#     return f"Error fetching token: {token_response.text}", 500

# # --------------------------
# # Enrollment Policy Service
# # --------------------------
# @app.route('/ENROLLMENTSERVER/DEVICEENROLLMENTWEBSERVICE.SVC', methods=['POST'])
# def enrollment_policy_service():
#     body_raw = request.data.decode('utf-8')
#     print("Enrollment Policy Request Body:", body_raw)
#     message_id_match = re.search(r'<a:MessageID>(.*?)<\/a:MessageID>', body_raw)
#     if message_id_match:
#         message_id = message_id_match.group(1)
#     else:
#         return Response("Invalid request: MessageID not found", status=400)

#     # Build SOAP envelope response using SOAP 1.2
#     soap_ns = "http://www.w3.org/2003/05/soap-envelope"
#     addressing_ns = "http://www.w3.org/2005/08/addressing"
#     policy_ns = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy"
#     envelope = Element("{%s}Envelope" % soap_ns)
#     header = SubElement(envelope, "{%s}Header" % soap_ns)
#     action = SubElement(header, "{%s}Action" % addressing_ns, {"s:mustUnderstand": "1"})
#     action.text = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPoliciesResponse"
#     relates = SubElement(header, "{%s}RelatesTo" % addressing_ns)
#     relates.text = message_id
#     body_el = SubElement(envelope, "{%s}Body" % soap_ns)
#     get_policies_response = SubElement(body_el, "GetPoliciesResponse", xmlns=policy_ns)
#     response_el = SubElement(get_policies_response, "response")
#     policies_el = SubElement(response_el, "policies")
#     policy_item = SubElement(policies_el, "policy")
#     policy_oid_ref = SubElement(policy_item, "policyOIDReference")
#     policy_oid_ref.text = "0"
#     cas_el = SubElement(policy_item, "cAs")
#     cas_el.set("{http://www.w3.org/2001/XMLSchema-instance}nil", "true")
#     attributes = SubElement(policy_item, "attributes")
#     common_name = SubElement(attributes, "commonName")
#     common_name.text = "CEPUnitTest"
#     policy_schema = SubElement(attributes, "policySchema")
#     policy_schema.text = "3"
#     certificate_validity = SubElement(attributes, "certificateValidity")
#     validity_period = SubElement(certificate_validity, "validityPeriodSeconds")
#     validity_period.text = "1209600"
#     renewal_period = SubElement(certificate_validity, "renewalPeriodSeconds")
#     renewal_period.text = "172800"
#     permission = SubElement(attributes, "permission")
#     enroll_el = SubElement(permission, "enroll")
#     enroll_el.text = "true"
#     auto_enroll_el = SubElement(permission, "autoEnroll")
#     auto_enroll_el.text = "false"
#     private_key_attributes = SubElement(attributes, "privateKeyAttributes")
#     minimal_key_length = SubElement(private_key_attributes, "minimalKeyLength")
#     minimal_key_length.text = "2048"
#     key_spec = SubElement(private_key_attributes, "keySpec")
#     key_spec.set("{http://www.w3.org/2001/XMLSchema-instance}nil", "true")
#     key_usage_property = SubElement(private_key_attributes, "keyUsageProperty")
#     key_usage_property.set("{http://www.w3.org/2001/XMLSchema-instance}nil", "true")
#     permissions_el = SubElement(private_key_attributes, "permissions")
#     permissions_el.set("{http://www.w3.org/2001/XMLSchema-instance}nil", "true")
#     algorithm_oid_ref = SubElement(private_key_attributes, "algorithmOIDReference")
#     algorithm_oid_ref.set("{http://www.w3.org/2001/XMLSchema-instance}nil", "true")
#     crypto_providers = SubElement(private_key_attributes, "cryptoProviders")
#     crypto_providers.set("{http://www.w3.org/2001/XMLSchema-instance}nil", "true")
#     revision = SubElement(attributes, "revision")
#     major_revision = SubElement(revision, "majorRevision")
#     major_revision.text = "101"
#     minor_revision = SubElement(revision, "minorRevision")
#     minor_revision.text = "0"
#     superseded_policies = SubElement(attributes, "supersededPolicies")
#     superseded_policies.set("{http://www.w3.org/2001/XMLSchema-instance}nil", "true")
#     private_key_flags = SubElement(attributes, "privateKeyFlags")
#     private_key_flags.set("{http://www.w3.org/2001/XMLSchema-instance}nil", "true")
#     subject_name_flags = SubElement(attributes, "subjectNameFlags")
#     subject_name_flags.set("{http://www.w3.org/2001/XMLSchema-instance}nil", "true")
#     enrollment_flags = SubElement(attributes, "enrollmentFlags")
#     enrollment_flags.set("{http://www.w3.org/2001/XMLSchema-instance}nil", "true")
#     general_flags = SubElement(attributes, "generalFlags")
#     general_flags.set("{http://www.w3.org/2001/XMLSchema-instance}nil", "true")
#     hash_algo_oid_ref = SubElement(attributes, "hashAlgorithmOIDReference")
#     hash_algo_oid_ref.text = "0"
#     ra_requirements = SubElement(attributes, "rARequirements")
#     ra_requirements.set("{http://www.w3.org/2001/XMLSchema-instance}nil", "true")
#     key_archival_attributes = SubElement(attributes, "keyArchivalAttributes")
#     key_archival_attributes.set("{http://www.w3.org/2001/XMLSchema-instance}nil", "true")
#     extensions = SubElement(attributes, "extensions")
#     extensions.set("{http://www.w3.org/2001/XMLSchema-instance}nil", "true")
#     cAs_response = SubElement(get_policies_response, "cAs")
#     cAs_response.set("{http://www.w3.org/2001/XMLSchema-instance}nil", "true")
#     oIDs = SubElement(get_policies_response, "oIDs")
#     oID = SubElement(oIDs, "oID")
#     value_el = SubElement(oID, "value")
#     value_el.text = "1.3.14.3.2.29"
#     group_el = SubElement(oID, "group")
#     group_el.text = "1"
#     oIDReferenceID = SubElement(oID, "oIDReferenceID")
#     oIDReferenceID.text = "0"
#     default_name = SubElement(oID, "defaultName")
#     default_name.text = "szOID_OIWSEC_sha1RSASign"

#     response_payload = tostring(envelope, encoding="utf-8", method="xml")
#     resp = Response(response_payload, status=200)
#     resp.headers['Content-Type'] = "application/soap+xml; charset=utf-8"
#     resp.headers['Content-Length'] = str(len(response_payload))
#     return resp

# # --------------------------
# # Enrollment Service Endpoint
# # --------------------------
# @app.route('/EnrollmentServer/Enrollment.svc', methods=['POST'])
# def enroll_service():
#     print("Enrollment Service endpoint hit")
#     try:
#         envelope = ET.fromstring(request.data)
#         # Look for the BinarySecurityToken element using its namespace
#         ns = {"wsse": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"}
#         token_elem = envelope.find('.//wsse:BinarySecurityToken', ns)
#         if token_elem is None:
#             return "BinarySecurityToken not found", 400
#         binary_security_token = token_elem.text.strip()
#         print("BinarySecurityToken:", binary_security_token)
#         try:
#             decoded_token = base64.b64decode(binary_security_token)
#             print("Decoded Token:", decoded_token)
#         except Exception as e:
#             print("Error decoding token:", e)
#             return "Invalid token format", 400
#         # Attempt to decode as JWT (if applicable)
#         try:
#             jwt_decoded = jwt.decode(decoded_token, options={"verify_signature": False})
#             print("JWT Decoded:", jwt_decoded)
#         except JOSEError as e:
#             print("JWT Decode Error:", e)
#             return "Invalid JWT token", 400

#         username = jwt_decoded.get("username") or jwt_decoded.get("sub")
#         print(f"Username from JWT: {username}")
#         # Here you would normally authenticate the client based on the token claims.

#         # For demonstration, sign a client certificate.
#         message_id = "urn:uuid:" + str(uuid.uuid4())
#         # Read root certificate and key from files
#         root_cert_der, root_key_der = read_certificate("identities/enrollment.crt", "identities/enrollment.key")
#         root_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, root_cert_der)
#         root_key = crypto.load_privatekey(crypto.FILETYPE_ASN1, root_key_der)
#         # Assume the token is a Base64-encoded PKCS#10 CSR
#         csr_raw = base64.b64decode(binary_security_token)
#         client_cert_der = create_signed_certificate(csr_raw, root_cert, root_key, "B7F49D0DCFD6D143B40F0440231AA2C7")
#         client_cert_fingerprint = hashlib.sha1(client_cert_der).hexdigest().upper()
#         root_cert_fingerprint = hashlib.sha1(root_cert_der).hexdigest().upper()
#         enrollment_type = "Federated"
#         cert_store = "System" if enrollment_type == "Device" else "User"
#         wap_provision_profile = f"""<?xml version="1.0" encoding="UTF-8"?>
#         <wap-provisioningdoc version="1.1">
#             <characteristic type="CertificateStore">
#                 <characteristic type="Root">
#                     <characteristic type="System">
#                         <characteristic type="{root_cert_fingerprint}">
#                             <parm name="EncodedCertificate" value="{base64.b64encode(root_cert_der).decode('utf-8')}" />
#                         </characteristic>
#                     </characteristic>
#                 </characteristic>
#                 <characteristic type="My">
#                     <characteristic type="{cert_store}">
#                         <characteristic type="{client_cert_fingerprint}">
#                             <parm name="EncodedCertificate" value="{base64.b64encode(client_cert_der).decode('utf-8')}" />
#                         </characteristic>
#                         <characteristic type="PrivateKeyContainer" />
#                     </characteristic>
#                 </characteristic>
#             </characteristic>
#             <characteristic type="APPLICATION">
#                 <parm name="APPID" value="w7" />
#                 <parm name="PROVIDER-ID" value="DEMO MDM" />
#                 <parm name="NAME" value="Windows MDM Demo Server" />
#                 <parm name="ADDR" value="https://example.com/ManagementServer/MDM.svc" />
#                 <parm name="ServerList" value="https://example.com/ManagementServer/ServerList.svc" />
#                 <parm name="ROLE" value="4294967295" />
#                 <parm name="BACKCOMPATRETRYDISABLED" />
#                 <parm name="DEFAULTENCODING" value="application/vnd.syncml.dm+xml" />
#                 <characteristic type="APPAUTH">
#                     <parm name="AAUTHLEVEL" value="CLIENT" />
#                     <parm name="AAUTHTYPE" value="DIGEST" />
#                     <parm name="AAUTHSECRET" value="dummy" />
#                     <parm name="AAUTHDATA" value="nonce" />
#                 </characteristic>
#                 <characteristic type="APPAUTH">
#                     <parm name="AAUTHLEVEL" value="APPSRV" />
#                     <parm name="AAUTHTYPE" value="DIGEST" />
#                     <parm name="AAUTHNAME" value="dummy" />
#                     <parm name="AAUTHSECRET" value="dummy" />
#                     <parm name="AAUTHDATA" value="nonce" />
#                 </characteristic>
#             </characteristic>
#         </wap-provisioningdoc>"""
#         wap_provision_profile_encoded = base64.b64encode(wap_provision_profile.encode("utf-8")).decode("utf-8")

#         # Build SOAP envelope for the enrollment response
#         soap_ns = "http://www.w3.org/2003/05/soap-envelope"
#         addressing_ns = "http://www.w3.org/2005/08/addressing"
#         trust_ns = "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
#         sec_ns = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
#         utility_ns = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
#         envelope_response = Element("{%s}Envelope" % soap_ns)
#         header = SubElement(envelope_response, "{%s}Header" % soap_ns)
#         action = SubElement(header, "{%s}Action" % addressing_ns, {"s:mustUnderstand": "1"})
#         action.text = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep"
#         relates = SubElement(header, "{%s}RelatesTo" % addressing_ns)
#         relates.text = message_id
#         security = SubElement(header, "{%s}Security" % sec_ns, {"s:mustUnderstand": "1"})
#         timestamp = SubElement(security, "{%s}Timestamp" % utility_ns, {"u:Id": "_0"})
#         created = SubElement(timestamp, "{%s}Created" % utility_ns)
#         created.text = "2018-11-30T00:32:59.420Z"
#         expires = SubElement(timestamp, "{%s}Expires" % utility_ns)
#         expires.text = "2018-12-30T00:37:59.420Z"
#         body_el = SubElement(envelope_response, "{%s}Body" % soap_ns)
#         rstr_collection = SubElement(body_el, "RequestSecurityTokenResponseCollection", xmlns=trust_ns)
#         rstr = SubElement(rstr_collection, "RequestSecurityTokenResponse")
#         token_type = SubElement(rstr, "TokenType")
#         token_type.text = "http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentToken"
#         disposition = SubElement(rstr, "DispositionMessage", xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment")
#         requested_token = SubElement(rstr, "RequestedSecurityToken")
#         binary_token = SubElement(requested_token, "BinarySecurityToken", 
#                                   {
#                                       "ValueType": "http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentProvisionDoc",
#                                       "EncodingType": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary"
#                                   },
#                                   xmlns=sec_ns)
#         binary_token.text = wap_provision_profile_encoded
#         request_id = SubElement(rstr, "RequestID", xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment")
#         request_id.text = "0"
#         response_payload = tostring(envelope_response, encoding="utf-8", method="xml")
#         print("Enrollment Response:", response_payload)
#         return Response(response_payload, mimetype="application/soap+xml; charset=utf-8")
#     except Exception as e:
#         print("Error processing enrollment request:", e)
#         return Response(f"Error: {str(e)}", status=500)

# # --------------------------
# # Helper Functions
# # --------------------------
# def read_certificate(cert_path, key_path):
#     with open(cert_path, "rb") as cert_file:
#         cert = cert_file.read()
#     with open(key_path, "rb") as key_file:
#         key = key_file.read()
#     return cert, key

# def create_signed_certificate(csr_raw, root_cert, root_key, device_id):
#     # Parse the CSR (assumed to be in DER format)
#     csr = crypto.load_certificate_request(crypto.FILETYPE_ASN1, csr_raw)
#     # Create a new certificate
#     cert = crypto.X509()
#     cert.set_serial_number(int(uuid.uuid4().int >> 64))  # Random serial number
#     cert.gmtime_adj_notBefore(0)
#     cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # 1 year validity
#     cert.set_issuer(root_cert.get_subject())
#     cert.set_subject(csr.get_subject())
#     cert.set_pubkey(csr.get_pubkey())
#     cert.sign(root_key, "sha256")
#     return crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)

# # --------------------------
# # Additional Endpoints
# # --------------------------
# @app.route('/devices', methods=['GET'])
# def devices():
#     result = list_devices()
#     return jsonify(result)

# @app.route('/status', methods=['GET'])
# def status():
#     return jsonify({"status": "MDM server running"})

# @app.route('/all-devices', methods=['GET'])
# def all_devices():
#     result = list_all_devcies()
#     return jsonify(result)

# # --------------------------
# # Run the Application
# # --------------------------
# if __name__ == "__main__":
#     app.run(host='0.0.0.0', port=5000)

