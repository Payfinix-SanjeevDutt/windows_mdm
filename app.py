from flask import Flask, request, jsonify, render_template, Response, redirect, render_template_string
import random
from cryptography import x509
import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from xml.etree.ElementTree import Element, SubElement, tostring, fromstring
from cryptography.hazmat.primitives import serialization
from jose import jwt, JOSEError
import hashlib
from xml.etree.ElementTree import Element, SubElement, tostring, fromstring
from lxml import etree
from xml.etree.ElementTree import fromstring
import uuid
import base64
import re
import requests
import xml.etree.ElementTree as ET
from config import Config
from OpenSSL import crypto
import json

app = Flask(__name__)
domain = "windowsmdm.sujanix.com"

oid_map = {
    "C": NameOID.COUNTRY_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
    "L": NameOID.LOCALITY_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "CN": NameOID.COMMON_NAME,
    "EMAILADDRESS": NameOID.EMAIL_ADDRESS,
}

@app.route("/")

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
                <AuthenticationServiceUrl>https://windowsmdm.sujanix.com/AuthenticationService.svc</AuthenticationServiceUrl>
                <EnrollmentPolicyServiceUrl>https://windowsmdm.sujanix.com/ENROLLMENTSERVER/DEVICEENROLLMENTWEBSERVICE.SVC</EnrollmentPolicyServiceUrl>
                <EnrollmentServiceUrl>https://windowsmdm.sujanix.com/EnrollmentServer/Enrollment.svc</EnrollmentServiceUrl>
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
    print("Enrollment Policy1 Request Body:", body)
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
    print("Enrollment Policy1 Response:", response)
    return response



def extract_message_id(xml_str):
    root = etree.fromstring(xml_str)
    ns = {"a": "http://www.w3.org/2005/08/addressing"}
    message_id = root.find(".//a:MessageID", namespaces=ns)
    return message_id.text if message_id is not None else str(uuid.uuid4())

def extract_pkcs10(xml_str):
    root = etree.fromstring(xml_str)
    ns = {
        "wsse": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
    }
    token_elem = root.find(
        ".//wsse:BinarySecurityToken[@ValueType='http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10']",
        namespaces=ns
    )
    return token_elem.text.strip() if token_elem is not None else None

def load_certificate(cert_path):
    """Load your self-signed certificate from file."""
    try:
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
        # Remove any extra whitespace/newlines if needed.
        return cert_data.decode('utf-8')
    except Exception as e:
        app.logger.exception("Error loading certificate file:")
        return None

def generate_provisioning_xml(cert_str):
    """
    Build a simple OMA provisioning XML that includes the certificate.
    The certificate is expected to be in PEM format.
    """
    # Base64-encode the certificate contents if needed.
    # (Sometimes the certificate might already be Base64-encoded between PEM headers.)
    # For example, you might remove the header/footer first.
    # Here we simply base64 encode the entire file.
    b64_cert = base64.b64encode(cert_str.encode()).decode()
    provisioning_xml = f"""<?xml version="1.0" encoding="utf-8"?>
                        <wap-provisioningdoc version="1.1">
                        <characteristic type="CertificateStore">
                            <characteristic type="Root">
                            <characteristic type="System">
                                <characteristic type="ProvisionedRootCert">
                                <parm name="EncodedCertificate" value="{b64_cert}" />
                                </characteristic>
                            </characteristic>
                            </characteristic>
                        </characteristic>
                        <characteristic type="CertificateStore">
                            <characteristic type="My">
                            <characteristic type="User">
                                <characteristic type="ProvisionedCert">
                                <parm name="EncodedCertificate" value="{b64_cert}" />
                                </characteristic>
                                <characteristic type="PrivateKeyContainer"/>
                            </characteristic>
                            </characteristic>
                        </characteristic>
                        <characteristic type="APPLICATION">
                            <parm name="APPID" value="w7"/>
                            <parm name="PROVIDER-ID" value="TestMDMServer"/>
                            <parm name="NAME" value="YourMDMServer"/>
                            <parm name="ADDR" value="https://windowsmdm.sujanix.com/EnrollmentServer/Enrollment.svc"/>
                            <!-- additional configuration parameters go here -->
                        </characteristic>
                        </wap-provisioningdoc>"""
    return provisioning_xml



@app.route('/ManagementServer/MDM.svc', methods=['POST'])
def manage_handler():
    try:
        # Read the HTTP request body as a UTF-8 string.
        body = request.get_data(as_text=True)
        print("HTTP Request Body:", body)
        # Retrieve the MessageID.
        message_id_match = re.search(r'<a:MessageID>(.*?)<\/a:MessageID>', body, re.DOTALL)
        if message_id_match:
            message_id = message_id_match.group(1).strip()
            print("Extracted MessageID:", message_id)
        else:
            return Response("MessageID not found", status=400)
        # Retrieve the BinarySecurityToken (CSR) – note: in production you would fully parse the XML.
        bst_match = re.search(
            r'<wsse:BinarySecurityToken ValueType="http:\/\/schemas\.microsoft\.com\/windows\/pki\/2009\/01\/enrollment#PKCS10" EncodingType="http:\/\/docs\.oasis-open\.org\/wss\/2004\/01\/oasis-200401-wss-wssecurity-secext-1\.0\.xsd#base64binary">(.*?)<\/wsse:BinarySecurityToken>',
            body,
            re.DOTALL
        )
        if bst_match:
            binary_security_token = bst_match.group(1).strip()
            print("Extracted BinarySecurityToken:", binary_security_token)
        else:
            binary_security_token = None
        # Retrieve the DeviceID.
        device_id_match = re.search(
            r'<ac:ContextItem Name="DeviceID"><ac:Value>(.*?)<\/ac:Value><\/ac:ContextItem>',
            body,
            re.DOTALL
        )
        if device_id_match:
            device_id = device_id_match.group(1).strip()
            print("Extracted DeviceID:", device_id)
        else:
            return Response("DeviceID not found", status=400)
        # Retrieve the EnrollmentType.
        enrollment_type_match = re.search(
            r'<ac:ContextItem Name="EnrollmentType"><ac:Value>(.*?)<\/ac:Value><\/ac:ContextItem>',
            body,
            re.DOTALL
        )
        if enrollment_type_match:
            enrollment_type = enrollment_type_match.group(1).strip()
            print("Extracted EnrollmentType:", enrollment_type)
        else:
            return Response("EnrollmentType not found", status=400)
        # Retrieve the SessionID.
        session_id_match = re.search(r'<SessionID>(.*?)<\/SessionID>', body, re.DOTALL)
        if session_id_match:
            session_id = session_id_match.group(1).strip()
            print("Extracted SessionID:", session_id)
        else:
            return Response("SessionID not found", status=400)
        # Retrieve the MsgID.
        msg_id_match = re.search(r'<MsgID>(.*?)<\/MsgID>', body, re.DOTALL)
        if msg_id_match:
            msg_id = msg_id_match.group(1).strip()
            print("Extracted MsgID:", msg_id)
        else:
            return Response("MsgID not found", status=400)
        # Decide which response to generate based on the presence of "com.microsoft/MDM/AADUserToken"
        if "com.microsoft/MDM/AADUserToken" in body:
            response_body = f"""<?xml version="1.0" encoding="UTF-8"?>
                                <SyncML xmlns="SYNCML:SYNCML1.2">
                                <SyncHdr>
                                <VerDTD>1.2</VerDTD>
                                <VerProto>DM/1.2</VerProto>
                                <SessionID>{session_id}</SessionID>
                                <MsgID>{msg_id}</MsgID>
                                <Target>
                                <LocURI>{device_id}</LocURI>
                                </Target>
                                <Source>
                                <LocURI>https://windowsmdm.sujanix.com/ManagementServer/MDM.svc</LocURI>
                                </Source>
                                </SyncHdr>
                                <SyncBody>
                                <Status>
                                <CmdID>1</CmdID>
                                <MsgRef>{msg_id}</MsgRef>
                                <CmdRef>0</CmdRef>
                                <Cmd>SyncHdr</Cmd>
                                <Data>200</Data>
                                </Status>
                                <Status>
                                <CmdID>2</CmdID>
                                <MsgRef>{msg_id}</MsgRef>
                                <CmdRef>2</CmdRef>
                                <Cmd>Alert</Cmd>
                                <Data>200</Data>
                                </Status>
                                <Status>
                                <CmdID>3</CmdID>
                                <MsgRef>{msg_id}</MsgRef>
                                <CmdRef>3</CmdRef>
                                <Cmd>Alert</Cmd>
                                <Data>200</Data>
                                </Status>
                                <Status>
                                <CmdID>4</CmdID>
                                <MsgRef>{msg_id}</MsgRef>
                                <CmdRef>4</CmdRef>
                                <Cmd>Alert</Cmd>
                                <Data>200</Data>
                                </Status>
                                <Status>
                                <CmdID>5</CmdID>
                                <MsgRef>{msg_id}</MsgRef>
                                <CmdRef>5</CmdRef>
                                <Cmd>Replace</Cmd>
                                <Data>200</Data>
                                </Status>
                                <Final />
                                </SyncBody>
                                </SyncML>"""
        else:
                response_body = f"""<?xml version="1.0" encoding="UTF-8"?>
                                <SyncML xmlns="SYNCML:SYNCML1.2">
                                <SyncHdr>VerDTD
                                <VerDTD>1.2</VerDTD>
                                <VerProto>DM/1.2</VerProto>
                                <SessionID>{session_id}</SessionID>
                                <MsgID>{msg_id}</MsgID>
                                <Target>
                                <LocURI>{device_id}</LocURI>
                                </Target>
                                <Source>
                                <LocURI>https://windowsmdm.sujanix.com/ManagementServer/MDM.svc</LocURI>
                                </Source>
                                </SyncHdr>
                                <SyncBody>
                                <Status>
                                <CmdID>1</CmdID>
                                <MsgRef>{msg_id}</MsgRef>
                                <CmdRef>0</CmdRef>
                                <Cmd>SyncHdr</Cmd>
                                <Data>200</Data>
                                </Status>
                                <Status>
                                <CmdID>2</CmdID>
                                <MsgRef>{msg_id}</MsgRef>
                                <CmdRef>2</CmdRef>
                                <Cmd>Alert</Cmd>
                                <Data>200</Data>
                                </Status>
                                <Status>
                                <CmdID>3</CmdID>
                                <MsgRef>{msg_id}</MsgRef>
                                <CmdRef>3</CmdRef>
                                <Cmd>Alert</Cmd>
                                <Data>200</Data>
                                </Status>
                                <Status>
                                <CmdID>4</CmdID>
                                <MsgRef>{msg_id}</MsgRef>
                                <CmdRef>4</CmdRef>
                                <Cmd>Replace</Cmd>
                                <Data>200</Data>
                                </Status>
                                <Final />
                                </SyncBody>
                </SyncML>"""
        # Remove newlines and tabs and encode to bytes.
        response_raw = response_body.replace("\n", "").replace("\t", "").encode("utf-8")
        resp = Response(response_raw, mimetype="application/vnd.syncml.dm+xml")
        resp.headers["Content-Length"] = str(len(response_raw))
        return resp
    except Exception as e:
        print("Error in ManageHandler:", e)
        return Response("Internal Server Error", status=500)
    
    
    
# @app.route('/EnrollmentServer/Enrollment.svc', methods=['POST'])
# def enroll_service():
#     print("NEW____ENROLLMENT_API___________")
#     try:
#         # 1. Read the HTTP request body as a UTF-8 string.
#         body = request.get_data(as_text=True)
#         print("HTTP Request Body:", body)
        
#         # 2. Extract the MessageID.
#         message_id_match = re.search(r'<a:MessageID>(.*?)<\/a:MessageID>', body, re.DOTALL)
#         if message_id_match:
#             message_id = message_id_match.group(1).strip()
#             print("Extracted MessageID:", message_id)
#         else:
#             return Response("MessageID not found", status=400)
        
#         # 3. Parse the SOAP XML envelope.
#         envelope = ET.fromstring(body)
        
#         # 4. Retrieve the <wsse:BinarySecurityToken> element.
#         wsse_ns = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
#         token_elem = envelope.find(f'.//{{{wsse_ns}}}BinarySecurityToken')
#         if token_elem is None:
#             return Response("BinarySecurityToken not found", status=400)
        
#         # 5. Validate the required attributes.
#         expected_value_type = "http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentUserToken"
#         expected_encoding_type = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary"
#         value_type = token_elem.get("ValueType")
#         encoding_type = token_elem.get("EncodingType")
#         if value_type != expected_value_type or encoding_type != expected_encoding_type:
#             error_msg = f"Invalid BinarySecurityToken attributes: ValueType: {value_type}, EncodingType: {encoding_type}"
#             print(error_msg)
#             return Response(error_msg, status=400)
        
#         # 6. Extract the BinarySecurityToken content.
#         binary_security_token = token_elem.text.strip()
#         print("Extracted BinarySecurityToken:", binary_security_token)
        
#         # 7. Extract DeviceID.
#         device_id_match = re.search(
#             r'<ac:ContextItem Name="DeviceID"><ac:Value>(.*?)<\/ac:Value><\/ac:ContextItem>',
#             body, re.DOTALL)
#         if device_id_match:
#             device_id = device_id_match.group(1).strip()
#             print("Extracted DeviceID:", device_id)
#         else:
#             return Response("DeviceID not found", status=400)
        
#         # 8. Extract EnrollmentType.
#         enrollment_type_match = re.search(
#             r'<ac:ContextItem Name="EnrollmentType"><ac:Value>(.*?)<\/ac:Value><\/ac:ContextItem>',
#             body, re.DOTALL)
#         if enrollment_type_match:
#             enrollment_type = enrollment_type_match.group(1).strip()
#             print("Extracted EnrollmentType:", enrollment_type)
#         else:
#             return Response("EnrollmentType not found", status=400)
        
#         # 9. Load raw Root CA certificate and private key from PEM files.
#         try:
#             with open("./identities/rootCA.crt", "rb") as cert_file:
#                 root_certificate_pem = cert_file.read()
#             with open("./identities/rootCA.key", "rb") as key_file:
#                 root_private_key_pem = key_file.read()
#             print("Root CA certificate and private key loaded successfully (PEM)")
#         except Exception as e:
#             print("Error loading certificates:", e)
#             return Response("Internal Server Error", status=500)
        
#         # 10. Parse the PEM certificates and convert them to DER.
#         try:
#             root_cert_parsed = crypto.load_certificate(crypto.FILETYPE_PEM, root_certificate_pem)
#             root_key_parsed = crypto.load_privatekey(crypto.FILETYPE_PEM, root_private_key_pem)
#             root_certificate_der = crypto.dump_certificate(crypto.FILETYPE_ASN1, root_cert_parsed)
#             root_private_key_der = crypto.dump_privatekey(crypto.FILETYPE_ASN1, root_key_parsed)
#             print("Parsed and converted Root CA certificate and private key to DER successfully")
#         except Exception as e:
#             print("Error parsing/converting certificates:", e)
#             return Response("Internal Server Error", status=500)
        
#         # 11. Decode the Base64 BinarySecurityToken to get the CSR raw bytes.
#         try:
#             decoded_token = base64.b64decode(binary_security_token)
#             print("Decoded BinarySecurityToken (hex):", decoded_token.hex()[:100])
#         except Exception as e:
#             print("Error decoding BinarySecurityToken:", e)
#             return Response("Invalid BinarySecurityToken format", status=400)

#         # Check if a certificate (instead of a CSR) was sent.
#         if decoded_token.strip().startswith(b"-----BEGIN CERTIFICATE-----"):
#             print("Received a certificate instead of a CSR.")
#             return Response("Expected a CSR but received a certificate. Please generate a proper CSR.", status=400)
        
#         # 12. Parse the CSR.
#         try:
#             # If the token is in PEM format.
#             if decoded_token.strip().startswith(b"-----BEGIN"):
#                 if b"CERTIFICATE REQUEST" in decoded_token:
#                     csr = x509.load_pem_x509_csr(decoded_token, default_backend())
#                     print("CSR loaded successfully (PEM)")
#                 else:
#                     return Response("Expected a CSR PEM, but got unexpected header", status=400)
#             else:
#                 # Assume DER format.
#                 csr = x509.load_der_x509_csr(decoded_token, default_backend())
#                 print("CSR loaded successfully (DER)")
#         except Exception as e:
#             print("Error parsing CSR:", e)
#             return Response("Invalid CSR", status=400)
                
#         # 13. Verify the CSR signature.
#         try:
#             csr.public_key().verify(
#                 csr.signature,
#                 csr.tbs_certrequest_bytes,
#                 padding.PKCS1v15(),
#                 csr.signature_hash_algorithm
#             )
#             print("CSR signature verified successfully")
#         except Exception as e:
#             print("CSR signature verification failed:", e)
#             return Response("CSR signature verification failed", status=400)
        
#         # 14. Create a client certificate.
#         not_before = datetime.now(timezone.utc) - timedelta(minutes=random.randint(0, 119))
#         not_after = not_before + timedelta(days=365)
#         certificate_builder = x509.CertificateBuilder()
#         certificate_builder = certificate_builder.subject_name(
#             x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, device_id)])
#         )
#         # Use the Root CA subject as the issuer.
#         issuer_components = root_cert_parsed.get_subject().get_components()
#         issuer_name = x509.Name([x509.NameAttribute(k.decode('utf-8'), v.decode('utf-8')) for k, v in issuer_components])
#         certificate_builder = certificate_builder.issuer_name(issuer_name)
#         certificate_builder = certificate_builder.public_key(csr.public_key())
#         certificate_builder = certificate_builder.serial_number(random.randint(1000, 1000000))
#         certificate_builder = certificate_builder.not_valid_before(not_before)
#         certificate_builder = certificate_builder.not_valid_after(not_after)
#         certificate_builder = certificate_builder.add_extension(
#             x509.KeyUsage(
#                 digital_signature=True,
#                 content_commitment=False,
#                 key_encipherment=False,
#                 data_encipherment=False,
#                 key_agreement=False,
#                 key_cert_sign=False,
#                 crl_sign=False,
#                 encipher_only=False,
#                 decipher_only=False
#             ),
#             critical=True
#         )
#         certificate_builder = certificate_builder.add_extension(
#             x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
#             critical=True
#         )
        
#         # Convert the OpenSSL key to a cryptography key.
#         root_key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, root_key_parsed)
#         root_key_crypto = serialization.load_pem_private_key(root_key_pem, password=None, backend=default_backend())
        
#         client_certificate = certificate_builder.sign(
#             private_key=root_key_crypto,
#             algorithm=hashes.SHA256(),
#             backend=default_backend()
#         )
        
#         client_cert_der = client_certificate.public_bytes(encoding=x509.Encoding.DER)
#         print("Client certificate signed successfully")
        
#         # 15. Compute SHA-1 fingerprints.
#         client_cert_fingerprint = hashlib.sha1(client_cert_der).hexdigest().upper()
#         print("Client Certificate Fingerprint:", client_cert_fingerprint)
#         identity_cert_fingerprint = hashlib.sha1(root_certificate_der).hexdigest().upper()
#         print("Identity Certificate Fingerprint:", identity_cert_fingerprint)
        
#         # 16. Determine CertStore.
#         cert_store = "System" if enrollment_type == "Device" else "User"
#         print("CertStore:", cert_store)
        
#         # 17. Generate WAP provisioning profile XML.
#         wap_provision_profile = f"""<?xml version="1.0" encoding="UTF-8"?>
#         <wap-provisioningdoc version="1.1">
#             <characteristic type="CertificateStore">
#                 <characteristic type="Root">
#                     <characteristic type="System">
#                         <characteristic type="{identity_cert_fingerprint}">
#                             <parm name="EncodedCertificate" value="{base64.b64encode(root_certificate_der).decode('utf-8')}" />
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
#                 <parm name="ADDR" value="https://windowsmdm.sujanix.com/ManagementServer/MDM.svc" />
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
#             <characteristic type="DMClient">
#                 <characteristic type="Provider">
#                     <characteristic type="DEMO MDM">
#                         <characteristic type="Poll">
#                             <parm name="NumberOfFirstRetries" value="8" datatype="integer" />
#                         </characteristic>
#                     </characteristic>
#                 </characteristic>
#             </characteristic>
#         </wap-provisioningdoc>"""
                
#         wap_provision_profile_raw = wap_provision_profile.replace("\n", "").replace("\t", "").encode("utf-8")
                
#      # 18. Create SOAP response payload.
#         response_xml = f"""<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
#             xmlns:a="http://www.w3.org/2005/08/addressing"
#             xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
#             <s:Header>
#                 <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep</a:Action>
#                 <a:RelatesTo>{message_id}</a:RelatesTo>
#                 <o:Security xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" s:mustUnderstand="1">
#                     <u:Timestamp u:Id="_0">
#                         <u:Created>2018-11-30T00:32:59.420Z</u:Created>
#                         <u:Expires>2018-12-30T00:37:59.420Z</u:Expires>
#                     </u:Timestamp>
#                 </o:Security>
#             </s:Header>
#             <s:Body>
#                 <RequestSecurityTokenResponseCollection xmlns="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
#                     <RequestSecurityTokenResponse>
#                         <TokenType>http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentToken</TokenType>
#                         <DispositionMessage xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment"></DispositionMessage>
#                         <RequestedSecurityToken>
#                             <BinarySecurityToken xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" 
#                                 ValueType="http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentProvisionDoc" 
#                                 EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary">
#                                 {base64.b64encode(wap_provision_profile_raw).decode('utf-8')}
#                             </BinarySecurityToken>
#                         </RequestedSecurityToken>
#                         <RequestID xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment">0</RequestID>
#                     </RequestSecurityTokenResponse>
#                 </RequestSecurityTokenResponseCollection>
#             </s:Body>
#         </s:Envelope>"""
#         print(response_xml)
        
#         resp = Response(response_xml, mimetype="application/soap+xml; charset=utf-8")
#         resp.headers["Content-Length"] = str(len(response_xml))
#         return resp

#     except Exception as e:
#         print("Error processing enrollment request:", e)
#         return Response("Internal Server Error", status=500)
     
@app.route('/EnrollmentServer/Enrollment.svc', methods=['POST'])
def enroll_service():
    print("NEW____ENROLLMENT_API___________")
    try:
        # 1. Read the HTTP request body as a UTF-8 string.
        body = request.get_data(as_text=True)
        print("HTTP Request Body:", body)

        # 2. Extract the MessageID.
        message_id_match = re.search(r'<a:MessageID>(.*?)<\/a:MessageID>', body, re.DOTALL)
        if message_id_match:
            message_id = message_id_match.group(1).strip()
            print("Extracted MessageID:", message_id)
        else:
            return Response("MessageID not found", status=400)

        # 3. Parse the SOAP XML envelope.
        envelope = ET.fromstring(body)

        # 4. Retrieve the <wsse:BinarySecurityToken> element.
        wsse_ns = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
        token_elem = envelope.find(f'.//{{{wsse_ns}}}BinarySecurityToken')
        if token_elem is None:
            return Response("BinarySecurityToken not found", status=400)

        # 5. Validate the required attributes.
        expected_value_type = "http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentUserToken"
        expected_encoding_type = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary"
        value_type = token_elem.get("ValueType")
        encoding_type = token_elem.get("EncodingType")
        if value_type != expected_value_type or encoding_type != expected_encoding_type:
            error_msg = f"Invalid BinarySecurityToken attributes: ValueType: {value_type}, EncodingType: {encoding_type}"
            print(error_msg)
            return Response(error_msg, status=400)

        # 6. Extract the BinarySecurityToken content.
        binary_security_token = token_elem.text.strip()
        print("Extracted BinarySecurityToken:", binary_security_token)

        # 7. Extract DeviceID.
        device_id_match = re.search(
            r'<ac:ContextItem Name="DeviceID"><ac:Value>(.*?)<\/ac:Value><\/ac:ContextItem>',
            body, re.DOTALL)
        if device_id_match:
            device_id = device_id_match.group(1).strip()
            print("Extracted DeviceID:", device_id)
        else:
            return Response("DeviceID not found", status=400)

        # 8. Extract EnrollmentType.
        enrollment_type_match = re.search(
            r'<ac:ContextItem Name="EnrollmentType"><ac:Value>(.*?)<\/ac:Value><\/ac:ContextItem>',
            body, re.DOTALL)
        if enrollment_type_match:
            enrollment_type = enrollment_type_match.group(1).strip()
            print("Extracted EnrollmentType:", enrollment_type)
        else:
            return Response("EnrollmentType not found", status=400)

        # 9. Load the server's Root CA certificate and private key (the CA identity).
        try:
            with open("./identities/rootCA.crt", "rb") as cert_file:
                root_certificate_pem = cert_file.read()
            with open("./identities/rootCA.key", "rb") as key_file:
                root_private_key_pem = key_file.read()
            print("Root CA certificate and private key loaded successfully (PEM)")
        except Exception as e:
            print("Error loading CA certificates:", e)
            return Response("Internal Server Error", status=500)

        # 10. Parse the CA certificate and key (PEM) and convert them to DER format.
        try:
            root_cert_parsed = crypto.load_certificate(crypto.FILETYPE_PEM, root_certificate_pem)
            root_key_parsed = crypto.load_privatekey(crypto.FILETYPE_PEM, root_private_key_pem)
            root_certificate_der = crypto.dump_certificate(crypto.FILETYPE_ASN1, root_cert_parsed)
            print("Parsed and converted Root CA certificate to DER successfully")
        except Exception as e:
            print("Error parsing/converting CA certificates:", e)
            return Response("Internal Server Error", status=500)

        # 11. Decode the BinarySecurityToken (Base64) to get the CSR raw bytes.
        try:
            decoded_token = base64.b64decode(binary_security_token)
            print("Decoded BinarySecurityToken (hex):", decoded_token.hex()[:100])
        except Exception as e:
            print("Error decoding BinarySecurityToken:", e)
            return Response("Invalid BinarySecurityToken format", status=400)

        # 12. Parse the CSR. In production, we require a valid CSR from the client.
        try:
            if not decoded_token.strip().startswith(b"-----BEGIN CERTIFICATE REQUEST-----"):
                print("Token does not start with '-----BEGIN CERTIFICATE REQUEST-----'. Rejecting enrollment.")
                return Response("Expected a CSR in PEM format from the client", status=400)
            else:
                csr = x509.load_pem_x509_csr(decoded_token, default_backend())
                print("CSR loaded successfully (PEM) from request.")
        except Exception as e:
            print("Error parsing CSR:", e)
            return Response("Invalid CSR", status=400)

        # 13. Verify the CSR signature.
        try:
            csr.public_key().verify(
                csr.signature,
                csr.tbs_certrequest_bytes,
                padding.PKCS1v15(),
                csr.signature_hash_algorithm
            )
            print("CSR signature verified successfully")
        except Exception as e:
            print("CSR signature verification failed:", e)
            return Response("CSR signature verification failed", status=400)

        # 14. Create a client certificate by signing the CSR with the CA's private key.
        not_before = datetime.utcnow() - timedelta(minutes=random.randint(0, 119))
        not_after = not_before + timedelta(days=365)
        certificate_builder = x509.CertificateBuilder()
        certificate_builder = certificate_builder.subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, device_id)])
        )
        # For the issuer, use the CA's subject.
        issuer_components = root_cert_parsed.get_subject().get_components()
        issuer_attributes = []
        for k, v in issuer_components:
            key_str = k.decode('utf-8').upper()  # Convert key to uppercase for oid_map
            value_str = v.decode('utf-8')
            oid = oid_map.get(key_str)
            if oid is None:
                try:
                    oid = x509.ObjectIdentifier(key_str)
                except Exception as ex:
                    print("Unable to convert issuer component key to OID:", key_str)
                    continue
            issuer_attributes.append(x509.NameAttribute(oid, value_str))
        issuer_name = x509.Name(issuer_attributes)
        certificate_builder = certificate_builder.issuer_name(issuer_name)
        certificate_builder = certificate_builder.public_key(csr.public_key())
        certificate_builder = certificate_builder.serial_number(random.randint(1000, 1000000))
        certificate_builder = certificate_builder.not_valid_before(not_before)
        certificate_builder = certificate_builder.not_valid_after(not_after)
        certificate_builder = certificate_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        certificate_builder = certificate_builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True
        )

        # Convert the CA key (from pyOpenSSL) to a cryptography key.
        root_key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, root_key_parsed)
        root_key_crypto = serialization.load_pem_private_key(root_key_pem, password=None, backend=default_backend())

        client_certificate = certificate_builder.sign(
            private_key=root_key_crypto,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )
        client_cert_der = client_certificate.public_bytes(encoding=serialization.Encoding.DER)
        print("Client certificate signed successfully")

        # 15. Compute SHA-1 fingerprints.
        client_cert_fingerprint = hashlib.sha1(client_cert_der).hexdigest().upper()
        print("Client Certificate Fingerprint:", client_cert_fingerprint)
        identity_cert_fingerprint = hashlib.sha1(root_certificate_der).hexdigest().upper()
        print("Identity Certificate Fingerprint:", identity_cert_fingerprint)

        # 16. Determine the certificate store based on EnrollmentType.
        cert_store = "System" if enrollment_type == "Device" else "User"
        print("CertStore:", cert_store)

        # 17. Generate WAP provisioning profile XML.
        wap_provision_profile = f"""<?xml version="1.0" encoding="UTF-8"?>
                                <wap-provisioningdoc version="1.1">
                                    <characteristic type="CertificateStore">
                                        <characteristic type="Root">
                                            <characteristic type="System">
                                                <characteristic type="{identity_cert_fingerprint}">
                                                    <parm name="EncodedCertificate" value="{base64.b64encode(root_certificate_der).decode('utf-8')}" />
                                                </characteristic>
                                            </characteristic>
                                        </characteristic>
                                    </characteristic>
                                    <characteristic type="My">
                                        <characteristic type="{cert_store}">
                                            <characteristic type="{client_cert_fingerprint}">
                                                <parm name="EncodedCertificate" value="{base64.b64encode(client_cert_der).decode('utf-8')}" />
                                            </characteristic>
                                            <characteristic type="PrivateKeyContainer" />
                                        </characteristic>
                                    </characteristic>
                                    <characteristic type="APPLICATION">
                                        <parm name="APPID" value="w7" />
                                        <parm name="PROVIDER-ID" value="DEMO MDM" />
                                        <parm name="NAME" value="Windows MDM Demo Server" />
                                        <parm name="ADDR" value="https://{domain}/ManagementServer/MDM.svc" />
                                        <parm name="ServerList" value="https://{domain}/ManagementServer/ServerList.svc" />
                                        <parm name="ROLE" value="4294967295" />
                                        <parm name="BACKCOMPATRETRYDISABLED" />
                                        <parm name="DEFAULTENCODING" value="application/vnd.syncml.dm+xml" />
                                        <characteristic type="APPAUTH">
                                            <parm name="AAUTHLEVEL" value="CLIENT" />
                                            <parm name="AAUTHTYPE" value="DIGEST" />
                                            <parm name="AAUTHSECRET" value="dummy" />
                                            <parm name="AAUTHDATA" value="nonce" />
                                        </characteristic>
                                        <characteristic type="APPAUTH">
                                            <parm name="AAUTHLEVEL" value="APPSRV" />
                                            <parm name="AAUTHTYPE" value="DIGEST" />
                                            <parm name="AAUTHNAME" value="dummy" />
                                            <parm name="AAUTHSECRET" value="dummy" />
                                            <parm name="AAUTHDATA" value="nonce" />
                                        </characteristic>
                                    </characteristic>
                                    <characteristic type="DMClient">
                                        <characteristic type="Provider">
                                            <characteristic type="DEMO MDM">
                                                <characteristic type="Poll">
                                                    <parm name="NumberOfFirstRetries" value="8" datatype="integer" />
                                                </characteristic>
                                            </characteristic>
                                        </characteristic>
                                    </characteristic>
                                </wap-provisioningdoc>"""

        wap_provision_profile_raw = wap_provision_profile.replace("\n", "").replace("\t", "").encode("utf-8")

        # 18. Create SOAP response payload.
        response_xml = f"""<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://www.w3.org/2005/08/addressing"
    xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep</a:Action>
        <a:RelatesTo>{message_id}</a:RelatesTo>
        <o:Security xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" s:mustUnderstand="1">
            <u:Timestamp u:Id="_0">
                <u:Created>2018-11-30T00:32:59.420Z</u:Created>
                <u:Expires>2018-12-30T00:37:59.420Z</u:Expires>
            </u:Timestamp>
        </o:Security>
    </s:Header>
    <s:Body>
        <RequestSecurityTokenResponseCollection xmlns="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
            <RequestSecurityTokenResponse>
                <TokenType>http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentToken</TokenType>
                <DispositionMessage xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment"></DispositionMessage>
                <RequestedSecurityToken>
                    <BinarySecurityToken xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                        ValueType="http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentProvisionDoc"
                        EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary">
                        {base64.b64encode(wap_provision_profile_raw).decode('utf-8')}
                    </BinarySecurityToken>
                </RequestedSecurityToken>
                <RequestID xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment">0</RequestID>
            </RequestSecurityTokenResponse>
        </RequestSecurityTokenResponseCollection>
    </s:Body>
</s:Envelope>"""
        print("Final Enrollment Response Payload:")
        print(response_xml)

        resp = Response(response_xml, mimetype="application/soap+xml; charset=utf-8")
        resp.headers["Content-Length"] = str(len(response_xml))
        return resp

    except Exception as e:
        print("Error processing enrollment request:", e)
        return Response("Internal Server Error", status=500)



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

