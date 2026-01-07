from flask import Blueprint, request, jsonify, session, render_template
import os
from dotenv import load_dotenv, set_key

admin_bp = Blueprint('admin', __name__)

ENV_PATH = '.env'

def is_admin_user():
    return session.get('is_admin')

@admin_bp.route('/config-page')
def config_page():
    if not is_admin_user(): return "Unauthorized", 403
    return render_template('admin/config.html')

@admin_bp.route('/get-env-config')
def get_env_config():
    if not is_admin_user(): return jsonify({"message": "Unauthorized"}), 403
    
    # keys to read
    keys = [
        'FW_IP', 'PA_API_KEY', 
        'LDAP_SERVER', 'LDAP_DOMAIN', 'LDAP_BASE_DN', 'LDAP_ADMIN_GROUP', 'LDAP_USER_GROUP',
        'ISE_IP', 'ISE_USER', 'ISE_PASSWORD',
        'SWITCH_USER', 'SWITCH_PASS', 'SWITCH_ENABLE',
        'SWITCH_USER_LOCAL', 'SWITCH_PASS_LOCAL'
    ]
    data = {}
    
    from dotenv import dotenv_values
    config = dotenv_values(ENV_PATH) 
    
    for k in keys:
        data[k] = config.get(k, '')
        
    return jsonify(data)

@admin_bp.route('/update-env-config', methods=['POST'])
def update_env_config():
    if not is_admin_user(): return jsonify({"message": "Unauthorized"}), 403
    
    data = request.json
    try:
        keys = [
            'FW_IP', 'PA_API_KEY', 
            'LDAP_SERVER', 'LDAP_DOMAIN', 'LDAP_BASE_DN', 'LDAP_ADMIN_GROUP', 'LDAP_USER_GROUP',
            'ISE_IP', 'ISE_USER', 'ISE_PASSWORD',
            'SWITCH_USER', 'SWITCH_PASS', 'SWITCH_ENABLE',
            'SWITCH_USER_LOCAL', 'SWITCH_PASS_LOCAL'
        ]
        
        for k in keys:
            if k in data:
                set_key(ENV_PATH, k, data[k])
                
        for k, v in data.items():
            if k in keys:
                os.environ[k] = v
                
        return jsonify({"status": "success", "message": "Configuration saved successfully."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
