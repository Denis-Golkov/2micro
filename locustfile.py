from locust import HttpUser, task, between
import uuid
import logging
import random

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def generate_domain_list():
    """Generate a list of 100 realistic domain names."""
    business_terms = [
        "tech", "digital", "systems", "solutions", "cloud", "data", "web",
        "app", "software", "consulting", "media", "group", "global", "net",
        "dev", "labs", "hub", "platform", "service", "analytics"
    ]
    
    descriptors = [
        "smart", "rapid", "prime", "peak", "elite", "bright", "blue", "red",
        "swift", "agile", "cyber", "meta", "next", "pro", "easy", "best",
        "first", "dynamic", "active", "modern"
    ]
    
    tlds = [
        "com", "net", "org", "io", "co", "tech", "app", "dev", "cloud",
        "ai"
    ]
    
    domains = set()
    while len(domains) < 100:
        descriptor = random.choice(descriptors)
        term = random.choice(business_terms)
        tld = random.choice(tlds)
        
        # Create variations of domain names
        domain_variations = [
            f"{descriptor}{term}.{tld}",
            f"{term}{descriptor}.{tld}",
            f"{descriptor}-{term}.{tld}",
            f"{term}-{descriptor}.{tld}"
        ]
        
        domain = random.choice(domain_variations).lower()
        domains.add(domain)
    
    return list(domains)

class MyUser(HttpUser):
    wait_time = between(1, 5)
    auth_token = None
    username = None
    password = "password123"  # Define a fixed password
    logger = logging.getLogger("LocustUser")
    domains = generate_domain_list()  # Generate domains once per class

    def on_start(self):
        """Register and then log in the user."""
        if not self.auth_token:
            # Only register and log in if there is no auth token
            self.register_user()
            self.login()

    def register_user(self):
        """Register a new user and return the username."""
        self.username = f"user_{uuid.uuid4().hex[:8]}"  # Generate a unique username
        payload = {"username": self.username, "password": self.password}
        headers = {"Content-Type": "application/json"}  # Add headers if required
        response = self.client.post("/register", json=payload, headers=headers)

        self.logger.info(f"Attempting to register user with payload: {payload}")
        self.logger.info(f"Response status: {response.status_code}, Response text: {response.text}")

        if response.status_code == 201:  # Assuming 201 means user creation success
            self.logger.info(f"User registration successful: {self.username}")
        else:
            self.logger.error(f"User registration failed: {response.status_code}, {response.text}")
            raise Exception("User registration failed")

    def login(self):
        """Login and store the authentication token."""
        payload = {"username": self.username, "password": self.password}
        headers = {"Content-Type": "application/json"}  # Ensure correct headers are added
        self.logger.info(f"Attempting login with payload: {payload}")
        
        response = self.client.post("/login", json=payload, headers=headers)

        # Log full response content for debugging
        self.logger.info(f"Response status: {response.status_code}, Response text: {response.text}")
        self.logger.debug(f"Response headers: {response.headers}")

        if response.status_code == 200:
            self.auth_token = response.json().get("token")
            self.logger.info(f"Login successful. Token: {self.auth_token}")
        else:
            self.logger.error(f"Login failed: {response.status_code}, {response.text}")
            if response.status_code == 500:
                self.logger.error(f"Server error details: {response.text}")
            raise Exception("Authentication failed")

    def post_request(self, endpoint, payload, success_status=(200, 201)):
        """Helper for POST requests with authentication."""
        headers = {"Authorization": f"Bearer {self.auth_token}"} if self.auth_token else {}
        response = self.client.post(endpoint, json=payload, headers=headers)
        self.logger.info(f"POST to {endpoint} with payload: {payload}, Response: {response.status_code}, {response.text}")
        
        # Check for 400 error and log detailed information
        if response.status_code == 400:
            self.logger.warning(f"Bad Request details: {response.text}")
        return response

    def get_request(self, endpoint, success_status=200):
        """Helper for GET requests with assertions and debug logs."""
        headers = {"Authorization": f"Bearer {self.auth_token}"} if self.auth_token else {}
        response = self.client.get(endpoint, headers=headers)
        if response.status_code != success_status:
            self.logger.error(f"GET {endpoint} failed: {response.status_code}, {response.text}")
        assert response.status_code == success_status, f"GET {endpoint} failed: {response.status_code}, {response.text}"
        return response

    @task(3)
    def homepage(self):
        self.get_request("/")  # Load the homepage

    @task(2)
    def register_page(self):
        self.register_user()  # Register a new user first
        self.login()  # Then log in with the same user

    @task(1)
    def dashboard_page(self):
        self.get_request("/dashboard")  # Load the dashboard page

    @task(2)
    def domain_add_page(self):
        self.get_request("/add_domain_page")
        for domain in self.domains:  # Use pre-generated domains
            payload = {"domain": domain}
            self.post_request("/add_domain", payload)

    @task(1)
    def add_domain_file_page(self):
        self.get_request("/domain_files")