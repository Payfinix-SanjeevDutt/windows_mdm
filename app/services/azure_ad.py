import requests
from flask import current_app
from app.config import Config


class AzureADService:
    @staticmethod
    def exchange_code_for_token(code):
        """Exchange authorization code for access and refresh tokens."""
        token_url = f"https://login.microsoftonline.com/{current_app.config['AZURE_AD_TENANT_ID']}/oauth2/v2.0/token"
        data = {
            "client_id": current_app.config["AZURE_AD_CLIENT_ID"],
            "client_secret": current_app.config["AZURE_AD_CLIENT_SECRET"],
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": current_app.config["REDIRECT_URI"]
        }
        response = requests.post(token_url, data=data)
        return response.json()
    
    @staticmethod
    def list_registered_devices(access_token):
        """Fetch the list of registered devices using Microsoft Graph API."""
        headers = {
            "Authorization": f"Bearer {access_token}"
        }
        url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices"
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Failed to fetch devices: {response.status_code} - {response.text}")


# def fetch_access_token():
#     print("DATA>>>>>>>>>>>", Config.AZURE_AD_TENANT_ID)
#     url = f"https://login.microsoftonline.com/{Config.AZURE_AD_TENANT_ID}/oauth2/v2.0/token"
#     data = {
#         "client_id": Config.AZURE_AD_CLIENT_ID,
#         "client_secret": Config.AZURE_AD_CLIENT_SECRET,
#         "grant_type": "client_credentials",
#         "scope": "https://graph.microsoft.com/.default"
#     }
#     response = requests.post(url, data=data)
#     response.raise_for_status()
#     # print("TOKENNNNNNNNNNNNNNNNNNNNN", response.json().get('access_token'))
#     return response.json().get('access_token')

# def fetch_device_details():
#     token = fetch_access_token()
#     headers = {"Authorization": f"Bearer {token}"}
#     url = f"{Config.AZURE_GRAPH_API_URL}/devices"
#     response = requests.get(url, headers=headers)
#     response.raise_for_status()
#     return response.json()
