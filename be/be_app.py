import logging
import logging.handlers
import os
from flask import Flask, request, jsonify
import json
import ssl
import socket
import requests
import yaml
from flask_apscheduler import APScheduler  # Import APScheduler
from urllib.parse import urlparse
from datetime import datetime
from elasticapm.contrib.flask import ElasticAPM


# --- Load Configuration ---
script_directory = os.path.dirname(os.path.abspath(__file__))
config_file_path = os.path.join(script_directory, 'be_config.yaml')

try:
    with open(config_file_path, 'r') as f:
        config = yaml.safe_load(f)
except FileNotFoundError:
    print(f"Error: Could not find configuration file at {config_file_path}")
    exit(1)

APP_NAME = config['app_name']
LOG_DIRECTORY = config['log_directory']
DOMAIN_FILE = config['domain_file']

# --- Setup Logging ---
os.makedirs(LOG_DIRECTORY, exist_ok=True)
logger = logging.getLogger(APP_NAME)
logger.setLevel(logging.DEBUG)

file_handler = logging.handlers.RotatingFileHandler(
    os.path.join(LOG_DIRECTORY, 'be_app.log'),
    maxBytes=10*1024*1024,
    backupCount=5
)
file_handler.setLevel(logging.DEBUG)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(console_handler)

app = Flask(__name__)
app.logger = logger

app.config['ELASTIC_APM'] = {
  'SERVICE_NAME': 'test',
  'API_KEY': 'Qm9MV0Q1VUJSQXhxN0pZbVZfcVM6MzFIcWhFYW9DS3o1QWlTLUR1X0U4UQ==',
  'SERVER_URL': 'https://test-fcd1e6.apm.us-east-1.aws.elastic.cloud:443',
  'ENVIRONMENT': 'test',
  'DEBUG': True
}

apm = ElasticAPM(app)

@app.route('/asd')
def asd():
    import time
    time.sleep(3)
    return 'ok', 200


# Initialize APScheduler
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

SEARCH_JOB_ID = "search_domains"
DEFAULT_INTERVAL = 3600  # 1 hour in seconds

def load_domains(username=None):
    """
    Load domains for a specific user or from the global domain file.

    Args:
        username (str, optional): Username to load domains for.
                                  If None, loads from the global domain file.

    Returns:
        list: List of domains
    """
    # If no username is provided, load from global domain file
    if username is None:
        logger.info("Loading domains from global domain file")
        if os.path.exists(DOMAIN_FILE):
            try:
                with open(DOMAIN_FILE, "w") as file: # changed to "w"
                    json.dump([{"domain":"google.com", "status":"up", "ssl_expiration":"3000", "ssl_issuer":"google"}], file, indent=4)
                logger.debug(f"Saved and Loaded  domains from global file")
                return [{"domain":"google.com", "status":"up", "ssl_expiration":"3000", "ssl_issuer":"google"}]
            except Exception as e:
                logger.error(f"Error loading global domain file: {e}")
        return []

    # Load user-specific domain file
    user_file = f"{username}_domain.json"
    logger.info(f"Loading domains for user: {username}")
    if os.path.exists(user_file):
        try:
            with open(user_file, "r") as file:
                domains = json.load(file)
                logger.debug(f"Loaded {len(domains)} domains for user {username}")
                return domains
        except Exception as e:
            logger.error(f"Error loading domain file for user {username}: {e}")
    return []

def save_domains(domains, username=None):
    """
    Save domains for a specific user or to the global domain file.

    Args:
        domains (list): List of domains to save
        username (str, optional): Username to save domains for.
                                  If None, saves to the global domain file.
    """
    # If no username is provided, save to global domain file
    if username is None:
        logger.info("Saving domains to global domain file")
        try:
            with open(DOMAIN_FILE, "w") as file:
                json.dump(domains, file, indent=4)
            logger.debug(f"Saved {len(domains)} domains to global file")
        except Exception as e:
            logger.error(f"Error saving to global domain file: {e}")
        return

    # Save to user-specific domain file
    user_file = f"{username}_domain.json"
    logger.info(f"Saving domains for user: {username}")
    try:
        with open(user_file, "w") as file:
            json.dump(domains, file, indent=4)
        logger.debug(f"Saved {len(domains)} domains for user {username}")
    except Exception as e:
        logger.error(f"Error saving domain file for user {username}: {e}")

def create_user_search_job(username):
    """
    Create a scheduled job for a specific user's domain monitoring.

    Args:
        username (str): Username to create a domain monitoring job for
    """
    def user_domain_search():
        """
        Perform domain search for a specific user.
        This function will be used as a job for individual users.
        """
        logger.info(f"Starting domain monitoring for user: {username}")
        domains = load_domains(username)

        if not domains:
            logger.warning(f"No domains found for user: {username}")
            return

        for domain in domains:
            try:
                domain["status"] = check_domain_status(domain["domain"])
                ssl_info = get_ssl_info(domain["domain"])
                domain["ssl_expiration"] = ssl_info["ssl_expiration"]
                domain["ssl_issuer"] = ssl_info["ssl_issuer"]
                logger.debug(f"Checked domain: {domain['domain']} - Status: {domain['status']}")
            except Exception as e:
                logger.error(f"Error checking domain {domain['domain']}: {e}")

        try:
            save_domains(domains, username)
            logger.info(f"Completed domain monitoring for user: {username}")
        except Exception as e:
            logger.error(f"Failed to save domain updates for user {username}: {e}")

    return user_domain_search

def get_ssl_info(domain):
    """Retrieve SSL expiration and issuer information for a domain."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                ssl_expiration = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                ssl_issuer = dict(x[0] for x in cert['issuer'])
                return {
                    "ssl_expiration": ssl_expiration.strftime("%Y-%m-%d"),
                    "ssl_issuer": ssl_issuer.get("organizationName", "Unknown")
                }
    except Exception as e:
        logger.exception(f"Error retrieving SSL info for {domain}: {e}")
        return {
            "ssl_expiration": "N/A",
            "ssl_issuer": "Unknown"
        }

def check_domain_status(domain):
    """Check if a domain is alive or down."""
    try:
        response = requests.get(f"https://{domain}", timeout=5)
        return "Up" if response.status_code == 200 else f"Down ({response.status_code})"
    except requests.RequestException as e:
        logger.debug(f"RequestException checking {domain}: {e}")
        return "Down"
    except Exception as e:
        logger.exception(f"Unexpected exception checking domain status for {domain}: {e}")
        return "Down"

@app.route('/api/get_domain_info', methods=['POST'])
def get_domain_info():
    """API endpoint to get domain info."""
    data = request.get_json()
    domain = data.get("domain")

    if not domain:
        logger.warning("Received request to /api/get_domain_info without domain")
        return jsonify({"error": "Domain is required"}), 400

    try:
        status = check_domain_status(domain)
        ssl_info = get_ssl_info(domain)
        return jsonify({
            "status": status,
            "ssl_expiration": ssl_info["ssl_expiration"],
            "ssl_issuer": ssl_info["ssl_issuer"]
        })
    except Exception as e:
        logger.exception(f"Error processing domain info request: {e}")
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.route('/api/update_schedule', methods=['POST'])
def update_schedule():
    """Update the search frequency or schedule."""
    data = request.get_json()
    frequency_type = data.get("frequency_type")
    value = data.get("value")
    username = data.get('username')

    if not username:
        logger.warning("Attempted to update schedule without logged-in user")
        return jsonify({"message": "User not logged in"}), 401

    try:
        # Remove existing job if it exists
        job_id = f"{SEARCH_JOB_ID}_{username}"
        if scheduler.get_job(job_id):
            scheduler.remove_job(job_id)
            logger.info(f"Removed existing job for user: {username}")

        # Create user-specific search function
        user_search_func = create_user_search_job(username)

        # Add new job based on the schedule type
        if frequency_type == "interval":
            interval_seconds = max(int(value), 3600)  # Minimum interval: 1 hour
            scheduler.add_job(
                id=job_id,
                func=user_search_func,
                trigger="interval",
                seconds=interval_seconds,
            )
            logger.info(f"Created interval job for user {username} with {interval_seconds}s interval")
        elif frequency_type == "time":
            schedule_time = datetime.strptime(value, "%H:%M").time()
            scheduler.add_job(
                id=job_id,
                func=user_search_func,
                trigger="cron",
                hour=schedule_time.hour,
                minute=schedule_time.minute,
            )
            logger.info(f"Created cron job for user {username} at {schedule_time}")

        return jsonify({"message": "Schedule updated successfully"}), 200
    except Exception as e:
        logger.error(f"Failed to update schedule for user {username}: {e}")
        return jsonify({"message": str(e)}), 500

if __name__ == "__main__":
    logger.info(f"Starting BE application: {APP_NAME}")
    app.run(debug=True, port=5001, host='0.0.0.0')