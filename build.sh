#!/bin/bash

# ==========================================
# NET-OPS Build & Run Script
# ==========================================

# 1. Define Environment Configuration
# Edit these values to configure your deployment
export FW_IP="CHANGE_ME_TO_REAL_IP"
export PA_API_KEY="CHANGE_ME_TO_REAL_KEY"

export LOCAL_ADMIN_USER="admin"
export LOCAL_ADMIN_PASS="admin123"

export LDAP_SERVER="10.3.0.152"
export LDAP_DOMAIN="net.lab"
export LDAP_BASE_DN="DC=net,DC=lab"
export LDAP_ADMIN_GROUP="CN=netadmin,CN=Users,DC=net,DC=lab"
export LDAP_USER_GROUP="CN=netlow,CN=Users,DC=net,DC=lab"

export FLASK_SECRET_KEY="production-secret-key-change-this"
export FLASK_DEBUG="False"

# ==========================================
# 2. Generate .env file
# ==========================================
echo "Generating .env file for Docker..."

# We write to docker/.env because docker-compose.yml in docker/ mounts ./.env
# We also write to root .env for consistency
cat > docker/.env <<EOL
FW_IP=$FW_IP
PA_API_KEY=$PA_API_KEY
LOCAL_ADMIN_USER=$LOCAL_ADMIN_USER
LOCAL_ADMIN_PASS=$LOCAL_ADMIN_PASS
LDAP_SERVER=$LDAP_SERVER
LDAP_DOMAIN=$LDAP_DOMAIN
LDAP_BASE_DN=$LDAP_BASE_DN
LDAP_ADMIN_GROUP=$LDAP_ADMIN_GROUP
LDAP_USER_GROUP=$LDAP_USER_GROUP
FLASK_SECRET_KEY=$FLASK_SECRET_KEY
FLASK_DEBUG=$FLASK_DEBUG
EOL

# Copy to root just in case
cp docker/.env .env

echo "Config generated successfully."

# ==========================================
# 3. Build and Run Docker Containers
# ==========================================
echo "Building and starting containers..."

# Run docker-compose from the project root, pointing to the file in docker/
docker-compose -f docker/docker-compose.yml up -d --build

echo "Deployment complete."
