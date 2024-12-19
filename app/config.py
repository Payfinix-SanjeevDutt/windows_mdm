import os
from dotenv import load_dotenv
load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'edad563bccd0896fdf438d700cf6a5f5a6d0f3334056237263c54e57280941be')
    # SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'postgresql://postgres:windowsDB123@windows-mdm.cja4g8gggrln.us-east-2.rds.amazonaws.com:5432/windows-mdm')
    # SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    AZURE_AD_CLIENT_ID = os.getenv('AZURE_CLIENT_ID')
    AZURE_AD_CLIENT_SECRET = os.getenv('AZURE_CLIENT_SECRET')
    AZURE_AD_TENANT_ID = os.getenv('AZURE_TENANT_ID') 
    REDIRECT_URI = os.getenv("REDIRECT_URI", "https://windowsmdm.sujanix.com/auth/callback")


    AZURE_GRAPH_API_URL = "https://graph.microsoft.com/v1.0"
   
    print("AZURE_TENANT_ID:", os.getenv("AZURE_TENANT_ID"))
    print("AZURE_CLIENT_ID:", os.getenv("AZURE_CLIENT_ID"))
    print("AZURE_CLIENT_SECRET:", os.getenv("AZURE_CLIENT_SECRET"))