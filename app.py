from flask import Flask, request, jsonify, render_template, Response, make_response, redirect, render_template_string
from lxml import etree
from jose import jwt, JOSEError
from xml.etree.ElementTree import Element, SubElement, tostring, fromstring
from utils.graph_api import *
import random
from datetime import datetime, timedelta, timezone
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
from OpenSSL import crypto
import json
import re
import hashlib
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.x509 import Certificate, CertificateSigningRequest, NameOID
from cryptography.hazmat.primitives.hashes import SHA1



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
                        <EnrollmentPolicyServiceUrl>
                           https://{domain}/ENROLLMENTSERVER/DEVICEENROLLMENTWEBSERVICE.SVC
                        </EnrollmentPolicyServiceUrl>
                        <EnrollmentServiceUrl>
                            https://{domain}/EnrollmentServer/Enrollment.svc
                        </EnrollmentServiceUrl>

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


@app.route('/ENROLLMENTSERVER/DEVICEENROLLMENTWEBSERVICE.SVC', methods=['POST'])
def enrollment_policy_service():
     # Read the HTTP request body
    body_raw = request.data
    body = body_raw.decode('utf-8')
    print("POLICY_BODY>>>>>>>>>>>>>>>>>>",body)
    # Retrieve the MessageID from the body for the response
    match = re.search(r'<a:MessageID>(.*?)<\/a:MessageID>', body)
    if match:
        message_id = match.group(1)
    else:
        return Response("Invalid request: MessageID not found", status=400)
    print("POLICY_MSG_ID", message_id)

    response_payload = f""" 
                        <s:Envelope
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
                        <GetPoliciesResponse
                        xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy">
                        <response>
                        <policyID />
                            <policyFriendlyName xsi:nil="true"
                            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/>
                            <nextUpdateHours xsi:nil="true"
                            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/>
                            <policiesNotChanged xsi:nil="true"
                            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/>
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
                </s:Envelope>
    
                """

    # Return the response
    response = Response(response_payload, status=200)
    response.headers['Content-Type'] = 'application/soap+xml; charset=utf-8'
    response.headers['Content-Length'] = str(len(response_payload))
    print("POLICY_RES____", response)
    return response

def parse_xml_value(xml, pattern):
    match = re.search(pattern, xml)
    if match:
        return match.group(1)
    return None

@app.route('/EnrollmentServer/Enrollment.svc', methods=['POST'])
def enroll_handler():
    try:
        # Read the HTTP request body
        body = request.data.decode('utf-8')

        # Extract MessageID from the body
        message_id_match = re.search(r'<a:MessageID>(.*?)</a:MessageID>', body)
        if not message_id_match:
            return Response("MessageID not found", status=400)
        message_id = message_id_match.group(1)
        print("ENNN___message_id",message_id,)
        # Extract BinarySecurityToken (contains CSR) from the body
        binary_security_token_match = re.search(
            r'<wsse:BinarySecurityToken .*?>(.*?)</wsse:BinarySecurityToken>', body
        )
        if not binary_security_token_match:
            return Response("BinarySecurityToken not found", status=400)
        binary_security_token = binary_security_token_match.group(1)
        print("ENNN__binary_security_token", binary_security_token)

        # Extract DeviceID from the body
        device_id_match = re.search(
            r'<ac:ContextItem Name="DeviceID"><ac:Value>(.*?)</ac:Value></ac:ContextItem>', body
        )
        if not device_id_match:
            return Response("DeviceID not found", status=400)
        device_id = device_id_match.group(1)
        print("ENNN___device_id", device_id)
        # Extract EnrollmentType from the body
        enrollment_type_match = re.search(
            r'<ac:ContextItem Name="EnrollmentType"><ac:Value>(.*?)</ac:Value></ac:ContextItem>', body
        )
        print("ENN__enrollment_type_match", enrollment_type_match)
        if not enrollment_type_match:
            return Response("EnrollmentType not found", status=400)
        enrollment_type = enrollment_type_match.group(1)
        print("ENNN____enrollment_type", enrollment_type)

        # Load Root CA certificate and private key
        with open('identity (1).crt', 'rb') as f:
            root_cert_data = f.read()
        with open('identity (1).key', 'rb') as f:
            root_key_data = f.read()

        root_cert = x509.load_pem_x509_certificate(root_cert_data, default_backend())
        root_private_key = serialization.load_pem_private_key(root_key_data, password=None, backend=default_backend())
        print("TILL___HERE")
        # Decode Base64 CSR
        csr_data = base64.b64decode(binary_security_token)
        csr = x509.load_pem_x509_csr(csr_data, default_backend())

        # Verify CSR signature
        if not csr.is_signature_valid:
            return Response("Invalid CSR signature", status=400)

        # Generate client certificate
        now = datetime.now(timezone.utc)
        not_before = now - timedelta(minutes=random.randint(0, 120))
        not_after = not_before + timedelta(days=365)
        client_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, device_id)]))
            .issuer_name(root_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False, content_commitment=False,
                                        key_agreement=False, data_encipherment=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False),
                          critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True)
            .sign(private_key=root_private_key, algorithm=SHA1(), backend=default_backend())
        )

        client_cert_data = client_cert.public_bytes(serialization.Encoding.DER)
        print("client_cert_data----", client_cert_data)

        # Generate fingerprints (SHA-1)
        signed_client_cert_fingerprint = hashlib.sha1(client_cert_data).hexdigest().upper()
        root_cert_fingerprint = hashlib.sha1(root_cert_data).hexdigest().upper()

        # Determine cert store type
        cert_store = "System" if enrollment_type == "Device" else "User"

        # Generate WAP provisioning profile
        wap_provision_profile = f'''<?xml version="1.0" encoding="UTF-8"?>
        <wap-provisioningdoc version="1.1">
            <characteristic type="CertificateStore">
                <characteristic type="Root">
                    <characteristic type="System">
                        <characteristic type="{root_cert_fingerprint}">
                            <parm name="EncodedCertificate" value="{base64.b64encode(root_cert_data).decode('utf-8')}" />
                        </characteristic>
                    </characteristic>
                </characteristic>
                <characteristic type="My">
                    <characteristic type="{cert_store}">
                        <characteristic type="{signed_client_cert_fingerprint}">
                            <parm name="EncodedCertificate" value="{base64.b64encode(client_cert_data).decode('utf-8')}" />
                        </characteristic>
                        <characteristic type="PrivateKeyContainer" />
                    </characteristic>
                </characteristic>
            </characteristic>
            <characteristic type="APPLICATION">
                <parm name="APPID" value="w7" />
                <parm name="PROVIDER-ID" value="DEMO MDM" />
                <parm name="NAME" value="Windows MDM Demo Server" />
                <parm name="ADDR" value="https://example.com/ManagementServer/MDM.svc" />
                <parm name="ServerList" value="https://example.com/ManagementServer/ServerList.svc" />
                <parm name="ROLE" value="4294967295" />
                <parm name="DEFAULTENCODING" value="application/vnd.syncml.dm+xml" />
            </characteristic>
        </wap-provisioningdoc>'''

        # Generate SOAP response
        response_payload = f'''<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://www.w3.org/2005/08/addressing"
            xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
            <s:Header>
                <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep</a:Action>
                <a:RelatesTo>{message_id}</a:RelatesTo>
            </s:Header>
            <s:Body>
                <RequestSecurityTokenResponseCollection xmlns="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
                    <RequestSecurityTokenResponse>
                        <TokenType>http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentToken</TokenType>
                        <RequestedSecurityToken>
                            <BinarySecurityToken xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" ValueType="http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentProvisionDoc" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary">{base64.b64encode(wap_provision_profile.encode('utf-8')).decode('utf-8')}</BinarySecurityToken>
                        </RequestedSecurityToken>
                        <RequestID xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment">0</RequestID>
                    </RequestSecurityTokenResponse>
                </RequestSecurityTokenResponseCollection>
            </s:Body>
        </s:Envelope>'''
        print("ENNN___RES____response_payload", response_payload)
        return Response(response_payload, content_type="application/soap+xml; charset=utf-8")

    except Exception as e:
        return Response(f"Error: {str(e)}", status=500)
    
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
