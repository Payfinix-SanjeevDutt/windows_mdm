import requests
from app.config import Config
def fetch_access_token():
    print("DATA>>>>>>>>>>>", Config.AZURE_AD_TENANT_ID)
    url = f"https://login.microsoftonline.com/{Config.AZURE_AD_TENANT_ID}/oauth2/v2.0/token"
    data = {
        "client_id": Config.AZURE_AD_CLIENT_ID,
        "client_secret": Config.AZURE_AD_CLIENT_SECRET,
        "grant_type": "client_credentials",
        "scope": "https://graph.microsoft.com/.default"
    }
    response = requests.post(url, data=data)
    response.raise_for_status()
    # print("TOKENNNNNNNNNNNNNNNNNNNNN", response.json().get('access_token'))
    return response.json().get('access_token')

def fetch_device_details():
    token = fetch_access_token()
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{Config.AZURE_GRAPH_API_URL}/devices"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()
