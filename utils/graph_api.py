import requests
from config import Config

def get_access_token():
    url = f"{Config.AUTHORITY_URL}/oauth2/v2.0/token"
    data = {
        "client_id": Config.CLIENT_ID,
        "client_secret": Config.CLIENT_SECRET,
        "grant_type": "client_credentials",
        # "scope": f"{Config.GRAPH_API_BASE_URL}/.default"
        "scope":  "https://graph.microsoft.com/.default"

    }
    # print("NEW_DATA>>>>>>>>>>", url , "VV",data)
    response = requests.post(url, data=data)
    
    response.raise_for_status()
    return response.json()["access_token"]

def enroll_device(device_id):
    access_token = get_access_token()
    url = f"{Config.GRAPH_API_BASE_URL}/deviceManagement/managedDevices/{device_id}"
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    response = requests.post(url, headers=headers)
    print("MY_RES___", response)
    return response.json()

def list_devices():
    access_token = get_access_token()
    url = f"{Config.GRAPH_API_BASE_URL}/deviceManagement/managedDevices"
    # print("URL>", url)
    # print("TOKENNN>", access_token)
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(url, headers=headers)
    # print("<<<RES>>>", response)
    return response.json()
