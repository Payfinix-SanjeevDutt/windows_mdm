from flask import Blueprint,request,jsonify
import requests
from handler import Handler


mdm_blueprint=Blueprint("windowsblueprint",__name__,url_prefix='/mdm')



    
    
@mdm_blueprint.route('/devices',methods=['GET','POST'])
def devices():
    """
    Endpoint to fetch all devices from Azure AD.
    """
    return Handler().all_devices()