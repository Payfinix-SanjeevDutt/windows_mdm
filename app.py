from flask import Flask, request, jsonify, render_template, Response, make_response, redirect, render_template_string
from lxml import etree
from jose import jwt, JOSEError
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
from OpenSSL import crypto
import json
import re


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

    # Create response payload
    # response_payload = f"""
    # <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
    #     <s:Header>
    #         <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPoliciesResponse</a:Action>
    #         <a:RelatesTo>{message_id}</a:RelatesTo>
    #     </s:Header>
    #     <s:Body xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    #         <GetPoliciesResponse xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy">
    #             <xcep:response xsi:nil="true" />
    #             <xcep:cAs xsi:nil="true" />
    #             <xcep:oIDs xsi:nil="true" />
    #         </GetPoliciesResponse>
    #     </s:Body>
    # </s:Envelope>
    # """
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
def enroll_service():
    print("NEW____ENROLLMENT_API___________")
    
    try:
        # Parse the incoming SOAP request
        envelope = ET.fromstring(request.data)
        
        # Extract the BinarySecurityToken
        binary_security_token_element = envelope.find(
            './/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}BinarySecurityToken'
        )
        if binary_security_token_element is None:
            return "BinarySecurityToken not found", 400
        
        binary_security_token = binary_security_token_element.text.strip()
        print("binary_security_token----------", binary_security_token)
        
        # Decode the BinarySecurityToken
        try:
            decoded_token = base64.b64decode(binary_security_token)
            print("decoded_token-------", decoded_token)
        except Exception as e:
            print("Error decoding token:", e)
            return "Invalid token format", 400
        
        # Attempt to decode as JWT
        try:
            jwt_decoded = jwt.decode(decoded_token, options={"verify_signature": False})
            print("JWT Decoded:", jwt_decoded)
        except JOSEError as e:
            print("JWT Decode Error:", e)
            return "Invalid JWT token", 400
        
        # Extract and print the username claim (if available)
        username = jwt_decoded.get("username") or jwt_decoded.get("sub")  # Adjust based on your JWT structure
        print(f"Username from JWT: {username}")
        
        # TODO: Authenticate the client using the extracted username and other claims
        
        # Generate the response (same as before)
        response = f"""
        <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
           xmlns:a="http://www.w3.org/2005/08/addressing"
           xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
           <s:Header>
              <a:Action s:mustUnderstand="1">
                 http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep
              </a:Action>
              <a:RelatesTo>urn:uuid:sample-uuid</a:RelatesTo>
           </s:Header>
           <s:Body>
              <RequestSecurityTokenResponseCollection xmlns="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
                 <RequestSecurityTokenResponse>
                    <TokenType>
                        http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentToken
                    </TokenType>
                    <RequestedSecurityToken>
                       <BinarySecurityToken
                          ValueType="http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentProvisionDoc"
                          EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary"
                          xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
                          {base64.b64encode(b'SampleProvisioningXML').decode('utf-8')}
                       </BinarySecurityToken>
                    </RequestedSecurityToken>
                    <RequestID>0</RequestID>
                 </RequestSecurityTokenResponse>
              </RequestSecurityTokenResponseCollection>
           </s:Body>
        </s:Envelope>
        """
        
        print("RESPONSE_ENROLLMENT>>>>", response)
        return Response(response, mimetype='application/soap+xml')
    
    except Exception as e:
        print("Error processing the request:", e)
        return "Internal Server Error", 500
    
    # print("____ENROLLMENT___APIII___________")
    # envelope = ET.fromstring(request.data)
    # binary_security_token = envelope.find(
    #     './/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}BinarySecurityToken'
    # ).text.strip()
    
    # print("binary_security_token----------", binary_security_token)
 
    # decoded_token = base64.b64decode(binary_security_token)
    # print("decoded_token-------", decoded_token)
    
    # credentials = decoded_token.decode('utf-8')
    # print("credentials-------", credentials)
    
    # username, password = credentials.split(':')
    # print(f"Username: {username}, Password: {password}")
    
    # # TODO: Authenticate the client using the extracted username and password
    # response = f"""
    # <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
    #    xmlns:a="http://www.w3.org/2005/08/addressing"
    #    xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
    #    <s:Header>
    #       <a:Action s:mustUnderstand="1">
    #          http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep
    #       </a:Action>
    #       <a:RelatesTo>urn:uuid:sample-uuid</a:RelatesTo>
    #    </s:Header>
    #    <s:Body>
    #       <RequestSecurityTokenResponseCollection xmlns="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
    #          <RequestSecurityTokenResponse>
    #             <TokenType>
    #                 http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentToken
    #             </TokenType>
    #             <RequestedSecurityToken>
    #                <BinarySecurityToken
    #                   ValueType="http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentProvisionDoc"
    #                   EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary"
    #                   xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
    #                   {base64.b64encode(b'SampleProvisioningXML').decode('utf-8')}
    #                </BinarySecurityToken>
    #             </RequestedSecurityToken>
    #             <RequestID>0</RequestID>
    #          </RequestSecurityTokenResponse>
    #       </RequestSecurityTokenResponseCollection>
    #    </s:Body>
    # </s:Envelope>
    # """
    
    # print("RESPONSE_ENROLLMENT>>>>", response)
    # return Response(response, mimetype='application/soap+xml')
    
    
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
