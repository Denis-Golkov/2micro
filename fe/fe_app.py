import logging
import logging.handlers
import os
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_from_directory
from urllib.parse import urlparse
import json
import yaml
import requests

# --- Load Configuration ---
with open('fe_config.yaml', 'r') as f:
    config = yaml.safe_load(f)

APP_NAME = config['app_name']
BACKEND_URL = config['backend_url']
LOG_DIRECTORY = config['log_directory']  # Added log directory to config
SECRET_KEY = config['secret_key']
DOMAIN_FILE = config['domain_file']
USERS_FILE = config['users_file']  #Added user file

# --- Setup Logging ---
os.makedirs(LOG_DIRECTORY, exist_ok=True)
logger = logging.getLogger(APP_NAME)  # Using app name as logger name
logger.setLevel(logging.DEBUG)

file_handler = logging.handlers.RotatingFileHandler(
    os.path.join(LOG_DIRECTORY, 'fe_app.log'),  # FE-specific log file
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

# --- Flask App ---
app = Flask(__name__)
app.secret_key = SECRET_KEY
app.logger = logger # Redirect Flask's internal logger

# --- Utility Functions ---
def load_domains(username=None):
    """Load domains for a specific user or from the global domain file."""
    domain_file = DOMAIN_FILE if username is None else f"{username}_domain.json"
    logger.info(f"Loading domains from {domain_file}") # Log domain loading
    if os.path.exists(domain_file):
        try:
            with open(domain_file, "r") as file:
                domains = json.load(file)
                logger.debug(f"Loaded {len(domains)} domains")
                return domains
        except Exception as e:
            logger.error(f"Error loading domain file: {e}")
            return [] # Return empty list on failure
    else:
        logger.info(f"Domain file not found: {domain_file}")
        return [] # Return empty list if file doesn't exist

def save_domains(domains, username=None):
    """Save domains for a specific user or to the global domain file."""
    domain_file = DOMAIN_FILE if username is None else f"{username}_domain.json"
    logger.info(f"Saving domains to {domain_file}") # Log domain saving
    try:
        with open(domain_file, "w") as file:
            json.dump(domains, file, indent=4)
            logger.debug(f"Saved {len(domains)} domains")
    except Exception as e:
        logger.error(f"Error saving domain file: {e}")

def load_users():
    """Load users from JSON file."""
    logger.info("Loading users from JSON file") # Log users loading
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, 'r') as f:
                users = json.load(f)
                logger.debug(f"Loaded {len(users)} users")
                return users
        except Exception as e:
            logger.error(f"Error loading users file: {e}")
            return [] # Return empty list if loading fails
    else:
        logger.info("Users file not found")
        return [] # Return empty list if file doesn't exist

def save_users(users):
    """Save users to JSON file."""
    logger.info("Saving users to JSON file") # Log users saving
    try:
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=4)
            logger.debug(f"Saved {len(users)} users")
    except Exception as e:
        logger.error(f"Error saving users file: {e}")

# --- Routes ---
@app.route('/')
def home():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get("username", "").strip()
        password = data.get("password", "").strip()

        if not username or not password:
            return jsonify({"message": "Username and password are required!"}), 400

        users = load_users()
        user = next((u for u in users if u["username"] == username and u["password"] == password), None)

        if user:
            session["user"] = username
            return jsonify({"message": "Login successful!"}), 200
        else:
            return jsonify({"message": "Invalid username or password!"}), 401
    except Exception as e:
        logger.exception(f"Login error: {e}")
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()

        if not username or not password:
            return jsonify({"message": "Username and password are required!"}), 400

        users = load_users()
        if any(u['username'] == username for u in users):
            return jsonify({"message": "Username already exists!"}), 409

        users.append({"username": username, "password": password})
        save_users(users)
        return jsonify({"message": "Registration successful!"}), 201
    except Exception as e:
        logger.exception(f"Registration error: {e}")
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))

@app.route('/get_domains', methods=['GET'])
def get_domains():
    """Return the list of domains for the logged-in user."""
    return jsonify(load_domains(session.get("user")))

@app.route('/dashboard')
def dashboard():
    username = session.get("user")  # Retrieve the username from the session
    if username:  # Check if the user is logged in
        return render_template('domain.html', username=username)
    else:
        return redirect("/")  # Redirect to login page if not logged in

@app.route('/add_domain', methods=['POST'])
def add_domain():
    """Add a domain to the monitoring list."""
    data = request.get_json()
    domain = data.get("domain")

    if not domain:
        return jsonify({"error": "Domain is required."}), 400

    # Clean domain by removing schemes and www
    parsed_url = urlparse(domain)
    clean_domain = parsed_url.netloc or parsed_url.path
    clean_domain = clean_domain.lstrip("www.")

    domains = load_domains(session.get("user"))

    if any(d["domain"] == clean_domain for d in domains):
        return jsonify({"error": "Domain already exists."}), 400

    #  Delegate domain status and SSL information retrieval to the backend
    try:
      response = requests.post(f"{BACKEND_URL}/api/get_domain_info", json={"domain": clean_domain})
      response.raise_for_status()
      domain_info = response.json()

      domain_entry = {
          "domain": clean_domain,
          "status": domain_info["status"],
          "ssl_expiration": domain_info["ssl_expiration"],
          "ssl_issuer": domain_info["ssl_issuer"],
      }

      domains.append(domain_entry)
      save_domains(domains, session.get("user"))

      return jsonify(domain_entry)
    except requests.exceptions.RequestException as e:
        logger.error(f"Error communicating with the backend: {e}")
        return jsonify({"error": "Failed to get domain info from backend"}), 500
    except Exception as e:
      logger.exception(f"An unexpected error occurred: {e}")
      return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500

@app.route('/add_domain_page')
def add_domain_page():
    """Render the add domain HTML page."""
    username = session.get("user")  # Retrieve the username from the session
    if username:  # Check if the user is logged in
        return render_template('add_domain.html', username=username)
    else:
        return redirect("/")  # Redirect to login page if not logged in

@app.route('/domain_files')
def domain_files():
    """Render the domain files HTML page."""
    username = session.get("user")  # Retrieve the username from the session

    if username:  # Check if the user is logged in
        return render_template('domain_files.html', username=username)
    else:
        return redirect("/")  # Redirect to login page if not logged in

@app.route('/remove_domain', methods=['POST'])
def remove_domain():
    """Remove a domain from the monitoring list."""
    data = request.get_json()
    domain = data.get("domain")

    if not domain:
        return jsonify({"error": "Domain is required."}), 400

    domains = load_domains(session.get("user"))

    # Filter out the domain from the list
    updated_domains = [d for d in domains if d["domain"] != domain]

    # Check if the domain was found and removed
    if len(updated_domains) == len(domains):
        return jsonify({"error": "Domain not found."}), 404

    # Save the updated list back to the file
    save_domains(updated_domains, session.get("user"))
    return jsonify({"message": f"Domain {domain} removed successfully."})

@app.route('/upload_domains', methods=['POST'])
def upload_domains():
    """Handle the upload of a TXT file with domains."""
    file = request.files.get('file')

    if not file:
        return jsonify({"error": "No file provided."}), 400

    # Ensure the file is a TXT file
    if not file.filename.endswith('.txt'):
        return jsonify({"error": "Please upload a .txt file."}), 400

    try:
        # Read the file content
        file_content = file.stream.read().decode('utf-8')
        domains_list = file_content.splitlines()

        # Clean and add domains
        domains = load_domains(session.get("user"))
        added_count = 0
        for domain in domains_list:
            domain = domain.strip()
            if domain and not any(d["domain"] == domain for d in domains):
                #  Delegate domain status and SSL information retrieval to the backend
                try:
                  response = requests.post(f"{BACKEND_URL}/api/get_domain_info", json={"domain": domain})
                  response.raise_for_status()
                  domain_info = response.json()

                  domain_entry = {
                      "domain": domain,
                      "status": domain_info["status"],
                      "ssl_expiration": domain_info["ssl_expiration"],
                      "ssl_issuer": domain_info["ssl_issuer"],
                  }
                  domains.append(domain_entry)
                  added_count += 1
                except requests.exceptions.RequestException as e:
                    logger.error(f"Error communicating with the backend: {e}")
                    continue # Skip to next domain
                except Exception as e:
                    logger.exception(f"An unexpected error occurred: {e}")
                    continue

        save_domains(domains, session.get("user"))
        return jsonify({"message": f"Successfully added {added_count} domains."}), 200

    except Exception as e:
        logger.exception(f"Error uploading domains: {e}")
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.route('/update_schedule', methods=['POST'])
def update_schedule():
    """Update the search frequency or schedule."""
    data = request.get_json()
    frequency_type = data.get("frequency_type")
    value = data.get("value")
    username = session.get('user')

    if not username:
        logger.warning("Attempted to update schedule without logged-in user")
        return jsonify({"message": "User not logged in"}), 401

    #  Delegate domain status and SSL information retrieval to the backend
    try:
        response = requests.post(f"{BACKEND_URL}/api/update_schedule", json={"frequency_type": frequency_type, "value":value, "username":username})
        response.raise_for_status()
        update_info = response.json()

        return update_info
    except requests.exceptions.RequestException as e:
        logger.error(f"Error communicating with the backend: {e}")
        return jsonify({"error": "Failed to get domain info from backend"}), 500
    except Exception as e:
      logger.exception(f"An unexpected error occurred: {e}")
      return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500

if __name__ == "__main__":
    logger.info(f"Starting FE application: {APP_NAME}")
    app.run(debug=True, port=8081, host='0.0.0.0')