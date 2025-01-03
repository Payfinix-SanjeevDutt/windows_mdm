import os
from dotenv import load_dotenv
import requests
load_dotenv()


class Config:
    CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
  
    CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
    TENANT_ID = os.getenv("AZURE_TENANT_ID")
    AUTHORITY_URL = f"https://login.microsoftonline.com/{TENANT_ID}"
    GRAPH_API_BASE_URL = "https://graph.microsoft.com/v1.0"
    REDIRECT_URI = "https://mdm.yourdomain.com/callback"    
    
    


