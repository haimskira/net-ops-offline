# 🛡️ Rule Manager Pro (NetOps Portal)

**Rule Manager Pro** is a centralized platform for automating firewall operations, specially designed for Palo Alto Networks environments. It allows users to search for objects, submit rule requests with pre-validation, and monitor traffic logs in real-time.

## 🌟 Key Features

### 🔍 Advanced Rule Management
*   **Proactive Shadow Check**: Prevents duplicate rules by checking against the firewall policy in real-time before submission.
*   **Dual Verification Engine**: Combines **API-based** verification with a **Local Database** fallback to ensure accurate detection even for complex object groups or FQDNs.
*   **Detailed Impact Analysis**: Instead of a simple error, users see a rich card displaying the conflicting rule, its action (Allow/Deny), and the matching source/destination.
*   **Service Group Support**: Fully supports selecting both individual services and Service Groups.

### ⚡ Smart Search & Objects
*   **Live Object Search**: Instant autocomplete for IPs, Address Groups, Services, and Tags.
*   **Auto-Zone Detection**: Automatically identifies source and destination zones based on IP routing tables.

### 🔐 Hybrid Security
*   **LDAP Integration**: Corporate authentication with role-based access.
*   **Local Emergency Login**: Fallback to local admin credentials defined in `.env` if LDAP is unavailable.

---

## 🚀 Getting Started

### Prerequisites
*   **Python 3.9+**
*   **Palo Alto Firewall** (API access required)

### 1. Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/haimskira/net-ops-v4.git
cd net-ops-v4
pip install -r requirements.txt
```

### 2. Configuration (`.env`)

The system relies on environment variables for security. These **MUST** be defined in a `.env` file in the root directory.

> ⚠️ **IMPORTANT**: The `.env` file contains secrets and is **NOT** included in Git. You must create it manually.

Create a file named `.env` and paste the following configuration:

```ini
# --- Firewall Settings (Required) ---
FW_IP=192.168.1.1
PA_API_KEY="YOUR_API_KEY_HERE"

# --- Emergency Local Access (Required) ---
# Use these credentials to log in locally
LOCAL_ADMIN_USER=admin
LOCAL_ADMIN_PASS=Admin123!

# --- Web Server Settings ---
FLASK_SECRET_KEY="ChangeMeToSomethingRandom"
FLASK_DEBUG=True
SYSLOG_PORT=514

# --- LDAP / Active Directory (Optional) ---
# LDAP_SERVER=10.0.0.5
# LDAP_DOMAIN=example.com
# LDAP_BASE_DN="DC=example,DC=com"
```

### 3. Running Locally

To start the application in development mode:

```bash
python app.py
```

*   The dashboard will be available at: `http://localhost:5100`
*   **Syslog Listener** will start on UDP Port `514`.

### 4. Running with Docker

```bash
docker-compose -f docker/docker-compose.yml up -d --build
```

---

## 📂 Project Structure

```text
net-ops-v4/
├── app.py                 # Application Entry Point
├── auth.py                # Authentication Logic
├── config.py              # Configuration Loader
├── .env                   # Environment Variables (Secrets)
├── requirements.txt       # Python Dependencies
├── data/                  # Persistent Storage (DBs)
├── docker/                # Docker Configuration & Scripts
├── managers/              # Database Models & Data Access Layer
├── routes/                # API Endpoints (Blueprints)
├── schemas/               # Pydantic Models for Validation
├── services/              # Core Business Logic (Firewall, Sync)
├── static/                # CSS, JS, Fonts
└── templates/             # HTML Templates
```

## 🛠️ Troubleshooting

**"Connection Attempt Failed" (WinError 10060)**
*   Ensure the `FW_IP` in `.env` is reachable from the server.
*   Check if a firewall or VPN is blocking access to the Palo Alto management interface.

**Database Location**
*   Databases are stored in the `data/` directory by default.
*   If you see an empty `data/traffic_log` folder, it is safe to delete. The actual file is `traffic_logs.db`.
