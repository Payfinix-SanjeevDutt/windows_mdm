from flask import jsonify
import requests
from utils.graph_api import get_access_token

class Handler:
    def __init__(self):
        pass
    def all_devices(self):
        try:
            # Get the access token
            access_token = get_access_token()
            
            # Define the API endpoint and headers
            graph_url = "https://graph.microsoft.com/v1.0/devices"
            headers = {
                "Authorization": f"Bearer {access_token}"
            }
            
            # Make the request to fetch devices
            response = requests.get(graph_url, headers=headers)
            
            # Handle the response
            if response.status_code == 200:
                devices = response.json()
                return jsonify({"status": "success", "devices": devices}), 200
            else:
                error_details = response.json()
                return jsonify({"status": "error", "details": error_details}), response.status_code
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500























    

    