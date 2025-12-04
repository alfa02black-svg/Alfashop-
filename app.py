import json
import os
import uuid
import secrets
import hashlib
from datetime import datetime, timedelta
from functools import wraps 

# Import necessary Flask components
from flask import Flask, render_template_string, request, redirect, url_for, session, jsonify, abort

# --- CUSTOM SECURITY FUNCTIONS (Replaces werkzeug.security) ---

def custom_generate_password_hash(password):
    """
    Generates a salted, hashed password using Python's standard libraries.
    NOTE: For high-security production apps, libraries like bcrypt or Argon2 
    are preferred for stronger key stretching.
    """
    # Generate a cryptographically secure salt (32 bytes = 64 hex chars)
    salt = secrets.token_hex(32)
    
    # Hash the combination of password and salt using SHA-256
    hashed_password = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
    
    # Store salt and hash separated by '$'
    return f"{salt}${hashed_password}"

def custom_check_password_hash(stored_hash, password):
    """
    Checks a plaintext password against a stored 'salt$hash' string.
    """
    if '$' not in stored_hash:
        # Invalid format
        return False
        
    salt, original_hash = stored_hash.split('$', 1)
    
    # Re-hash the provided password with the stored salt
    check_hash = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
    
    # Use secrets.compare_digest for a timing-attack safe comparison
    return secrets.compare_digest(check_hash, original_hash)


# --- CONFIGURATION AND CONSTANTS ---

# Define Roles
ADMIN_ROLE = 'admin'
USER_ROLE = 'user'

# New constraint: Maximum registrations allowed per IP address
MAX_REGISTRATIONS_PER_IP = 2 

# Mock Database Structure 
# Stored as: { 'username': {'password_hash': 'salt$hash', 'role': 'admin/user', 'is_blocked': true/false} }
USER_DB = {
    'admin': {
        # Using the new custom hashing function for default admin password
        'password_hash': custom_generate_password_hash('adminpassword'), 
        'role': ADMIN_ROLE, 
        'is_blocked': False
    },
    'user1': {
        'password_hash': custom_generate_password_hash('userpassword'), 
        'role': USER_ROLE, 
        'is_blocked': False
    }
}

# New DB to track registrations by IP address.
# { 'ip_address': count }
IP_REGISTRATION_COUNT = {}

# Initialize IP count for existing users (assuming they registered from a single mock IP)
for username in USER_DB:
    # A simplified way to initialize the count for existing users
    # In a real app, the IP would be stored alongside user data.
    mock_ip = "127.0.0.1" 
    IP_REGISTRATION_COUNT[mock_ip] = IP_REGISTRATION_COUNT.get(mock_ip, 0) + 1


app = Flask(__name__)

# --- APP CONFIGURATION ---
app.secret_key = secrets.token_hex(32) 
app.permanent_session_lifetime = timedelta(days=1)


# --- TEMPLATE STRINGS (HTML + Tailwind CSS) ---

# HTML Template for Login and Registration Pages
AUTH_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Web App - Auth</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700;900&display=swap');
        body { font-family: 'Inter', sans-serif; }
    </style>
</head>
<body class="bg-gray-50 flex items-center justify-center min-h-screen p-4">

    <div id="auth-card" class="w-full max-w-md bg-white p-8 md:p-10 rounded-xl shadow-2xl transition-all duration-300">
        <h1 class="text-3xl font-bold text-center mb-6 text-gray-800">
            {% if view == 'login' %}
                Professional Login
            {% else %}
                Secure Registration
            {% endif %}
        </h1>

        {% if error %}
        <div class="p-3 mb-4 text-sm text-red-700 bg-red-100 rounded-lg text-center" role="alert">
            {{ error }}
        </div>
        {% endif %}

        {% if view == 'login' %}
        <form method="POST" action="{{ url_for('login') }}" class="space-y-6">
            <div>
                <label for="username" class="block text-sm font-medium text-gray-700">Username</label>
                <input type="text" id="username" name="username" required
                       class="mt-1 block w-full px-4 py-2 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 transition duration-150">
            </div>
            <div>
                <label for="password" class="block text-sm font-medium text-gray-700">Password</label>
                <input type="password" id="password" name="password" required
                       class="mt-1 block w-full px-4 py-2 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 transition duration-150">
            </div>
            <button type="submit"
                    class="w-full flex justify-center py-2 px-4 border border-transparent rounded-lg shadow-sm text-lg font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition duration-150 transform hover:scale-[1.01]">
                Sign In
            </button>
        </form>

        <p class="mt-6 text-center text-sm text-gray-600">
            Need an account? 
            <a href="{{ url_for('register') }}" class="font-medium text-indigo-600 hover:text-indigo-500">
                Register now
            </a>
        </p>
        {% endif %}
        
        {% if view == 'register' %}
        <form method="POST" action="{{ url_for('register') }}" class="space-y-6">
            <div>
                <label for="reg-username" class="block text-sm font-medium text-gray-700">Choose Username</label>
                <input type="text" id="reg-username" name="username" required
                       class="mt-1 block w-full px-4 py-2 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 transition duration-150">
            </div>
            <div>
                <label for="reg-password" class="block text-sm font-medium text-gray-700">Password</label>
                <input type="password" id="reg-password" name="password" required
                       class="mt-1 block w-full px-4 py-2 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 transition duration-150">
            </div>
            <button type="submit"
                    class="w-full flex justify-center py-2 px-4 border border-transparent rounded-lg shadow-sm text-lg font-medium text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 transition duration-150 transform hover:scale-[1.01]">
                Create Account
            </button>
        </form>

        <p class="mt-6 text-center text-sm text-gray-600">
            Already registered? 
            <a href="{{ url_for('index') }}" class="font-medium text-green-600 hover:text-green-500">
                Sign in
            </a>
        </p>
        {% endif %}
    </div>

</body>
</html>
"""

# HTML Template for the Dashboard (User/Admin View)
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ role.capitalize() }} Dashboard | Python App</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700;900&display=swap');
        body { font-family: 'Inter', sans-serif; }
    </style>
</head>
<body class="bg-gray-100 min-h-screen">

    <!-- Header & Navigation -->
    <nav class="bg-white shadow-md">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex justify-between items-center h-16">
                <!-- Logo/Title -->
                <div class="flex-shrink-0">
                    <span class="text-2xl font-extrabold {% if role == 'admin' %}text-red-600{% else %}text-indigo-600{% endif %}">
                        {{ role.capitalize() }} Panel
                    </span>
                </div>
                
                <!-- Search Bar -->
                <div class="flex-1 max-w-lg mx-2 sm:mx-8 block">
                    <div class="relative">
                        <input type="text" id="search-input" placeholder="Search products or features..."
                               class="w-full py-2 pl-10 pr-4 border border-gray-300 rounded-full focus:outline-none focus:ring-2 focus:ring-indigo-500"
                               onkeyup="filterProducts()">
                        <svg class="absolute left-3 top-2.5 h-5 w-5 text-gray-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                            <path fill-rule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clip-rule="evenodd" />
                        </svg>
                    </div>
                </div>

                <!-- User Info & Logout -->
                <div class="flex items-center space-x-4">
                    <span class="text-gray-700 font-medium hidden sm:block">Hello, {{ username }}!</span>
                    <a href="{{ url_for('logout') }}" 
                       class="px-4 py-2 border border-transparent text-sm font-medium rounded-lg text-white bg-red-500 hover:bg-red-600 transition duration-150 shadow-md">
                        Logout
                    </a>
                </div>
            </div>
        </div>
    </nav>

    <!-- Main Content Area -->
    <main class="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div class="px-4 py-6 sm:px-0">
            
            <header class="mb-8">
                <h2 class="text-4xl font-extrabold text-gray-900">
                    {% if role == 'admin' %}
                        <span class="text-red-600">Admin Control Panel</span>
                    {% else %}
                        Your User Dashboard
                    {% endif %}
                </h2>
                <p class="mt-2 text-xl text-gray-600">
                    Manage your account and explore the offerings.
                </p>
            </header>

            <!-- Admin-Specific Management Panel -->
            {% if role == 'admin' %}
            <div class="bg-white p-6 rounded-xl shadow-xl border-t-4 border-red-500 mb-8">
                <h3 class="text-2xl font-semibold text-red-800 mb-6">User and Role Management</h3>
                
                <!-- Add Admin Form -->
                <div class="mb-8 p-4 bg-red-50 border border-red-200 rounded-lg">
                    <h4 class="text-xl font-bold mb-3 text-red-700">Add New Administrator</h4>
                    <form id="add-admin-form" class="flex flex-col md:flex-row gap-3">
                        <input type="text" name="username" placeholder="New Admin Username" required class="flex-1 px-4 py-2 border rounded-lg focus:ring-red-500">
                        <input type="password" name="password" placeholder="New Admin Password" required class="flex-1 px-4 py-2 border rounded-lg focus:ring-red-500">
                        <button type="submit" class="w-full md:w-auto px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition">
                            Create Admin
                        </button>
                    </form>
                </div>
                
                <!-- User List Table -->
                <h4 class="text-xl font-bold mb-3 text-gray-700">All Registered Users</h4>
                <div class="overflow-x-auto">
                    <table class="min-w-full divide-y divide-gray-200">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Username</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Role</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                            </tr>
                        </thead>
                        <tbody id="user-table-body" class="bg-white divide-y divide-gray-200">
                            {% for user_key, user_data in users.items() %}
                            <tr id="user-row-{{ user_key }}">
                                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{{ user_key }}</td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                    <span id="role-{{ user_key }}" class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full 
                                        {% if user_data.role == 'admin' %}bg-red-100 text-red-800{% else %}bg-indigo-100 text-indigo-800{% endif %}">
                                        {{ user_data.role.capitalize() }}
                                    </span>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm">
                                    <span id="status-{{ user_key }}" class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full 
                                        {% if user_data.is_blocked %}bg-gray-200 text-gray-800{% else %}bg-green-100 text-green-800{% endif %}">
                                        {{ 'Blocked' if user_data.is_blocked else 'Active' }}
                                    </span>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                                    {% if user_key != username %}
                                        <button onclick="toggleBlockStatus('{{ user_key }}', '{{ 'true' if user_data.is_blocked else 'false' }}')" 
                                                id="block-btn-{{ user_key }}"
                                                class="text-white font-medium py-1 px-3 rounded-lg text-xs transition duration-150 shadow-md 
                                                {% if user_data.is_blocked %}bg-green-500 hover:bg-green-600{% else %}bg-gray-500 hover:bg-gray-600{% endif %}">
                                            {{ 'Unblock' if user_data.is_blocked else 'Block' }}
                                        </button>
                                    {% else %}
                                        <span class="text-gray-400">Self</span>
                                    {% endif %}
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
            {% endif %}

            <!-- Store View (Visible to both User and Admin) -->
            <div class="bg-white shadow-xl rounded-xl p-6">
                <h3 class="text-2xl font-semibold text-gray-900 mb-6 border-b pb-2">
                    Store & Products (Clickable Placeholders)
                </h3>
                
                <div id="product-list" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
                    <!-- Product Cards rendered via Jinja loop -->
                    {% for product in products %}
                    <div class="product-card bg-gray-50 p-5 rounded-lg shadow-md hover:shadow-xl transition duration-300 border border-gray-200"
                         data-name="{{ product.name.lower() }}">
                        <h4 class="text-xl font-bold text-indigo-700 mb-2">{{ product.name }}</h4>
                        <p class="text-gray-600 mb-3">{{ product.description }}</p>
                        <div class="flex justify-between items-center">
                            <span class="text-2xl font-extrabold text-green-600">${{ "{:.2f}".format(product.price) }}</span>
                            <!-- ADDED: onclick handler for interactivity feedback -->
                            <button onclick="addToCart('{{ product.name }}')" class="bg-indigo-500 text-white px-4 py-2 rounded-lg text-sm hover:bg-indigo-600 transition">
                                Add to Cart
                            </button>
                        </div>
                    </div>
                    {% endfor %}
                </div>

                <div id="no-results" class="hidden text-center mt-10 p-5 bg-yellow-100 rounded-lg text-yellow-800">
                    <p class="font-bold text-lg">No Results Found</p>
                    <p>Try refining your search terms.</p>
                </div>
            </div>

        </div>
    </main>
    
    <!-- Custom Modal/Message Box -->
    <div id="message-modal" class="fixed inset-0 bg-gray-600 bg-opacity-75 hidden items-center justify-center p-4 z-50">
        <div class="bg-white p-6 rounded-lg shadow-2xl max-w-sm w-full">
            <h3 class="text-xl font-bold text-gray-800 mb-4" id="modal-title">Action Feedback</h3>
            <p class="text-gray-600 mb-6" id="modal-content">Action logged in console.</p>
            <button onclick="document.getElementById('message-modal').classList.add('hidden'); document.getElementById('message-modal').classList.remove('flex');"
                    class="w-full py-2 px-4 bg-indigo-600 text-white font-medium rounded-lg hover:bg-indigo-700">
                Close
            </button>
        </div>
    </div>


    <!-- JavaScript for Dynamic Interactivity and Admin Actions -->
    <script>
        /** Shows a custom modal instead of using the forbidden alert() function. */
        function showMessage(title, message) {
            document.getElementById('modal-title').textContent = title;
            document.getElementById('modal-content').textContent = message;
            document.getElementById('message-modal').classList.remove('hidden');
            document.getElementById('message-modal').classList.add('flex');
        }
        
        /** Mock function for 'Add to Cart' interactivity. */
        function addToCart(productName) {
            console.log("LOG: Attempted to add '" + productName + "' to cart.");
            showMessage("Product Added!", "'" + productName + "' functionality is mocked. Check console for log.");
        }

        /** Filters the product cards based on the text entered in the search bar. */
        function filterProducts() {
            const input = document.getElementById('search-input');
            const filter = input.value.toLowerCase();
            const productList = document.getElementById('product-list');
            const cards = productList.getElementsByClassName('product-card');
            const noResults = document.getElementById('no-results');
            let found = false;

            for (let i = 0; i < cards.length; i++) {
                const productName = cards[i].getAttribute('data-name');
                if (productName.includes(filter)) {
                    cards[i].style.display = ""; // Show the card
                    found = true;
                } else {
                    cards[i].style.display = "none"; // Hide the card
                }
            }

            if (!found && filter !== '') {
                noResults.classList.remove('hidden');
            } else {
                noResults.classList.add('hidden');
            }
        }
        
        // --- ADMIN DYNAMIC FUNCTIONS (Client-side API calls) ---

        // Handle Add Admin Form Submission
        document.getElementById('add-admin-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const form = e.target;
            const username = form.username.value;
            const password = form.password.value;

            // Simple check to prevent self-creation conflict with the DB key
            if (username === '{{ username }}') {
                showMessage("Error", "Cannot create an admin with your own username.");
                return;
            }

            const response = await fetch('{{ url_for('api_add_admin') }}', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            const result = await response.json();

            if (response.ok) {
                // Since this uses Jinja templates rendered once, a refresh is needed to see the new user in the table
                showMessage("Success", result.message + ". Please refresh the page to see the new administrator.");
                form.reset();
            } else {
                showMessage("Error", result.error || "Failed to add admin.");
            }
        });

        // Handle Block/Unblock Button Click
        async function toggleBlockStatus(username, isBlockedString) {
            const isBlocked = isBlockedString === 'true'; // Convert string to boolean
            const newStatus = !isBlocked;
            
            const response = await fetch('{{ url_for('api_block_user') }}', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, is_blocked: newStatus })
            });
            const result = await response.json();

            if (response.ok) {
                // Client-side UI Update (Without Page Reload)
                const statusSpan = document.getElementById(`status-${username}`);
                const button = document.getElementById(`block-btn-${username}`);
                
                // Update button and status display
                if (newStatus) {
                    statusSpan.textContent = 'Blocked';
                    statusSpan.classList.remove('bg-green-100', 'text-green-800');
                    statusSpan.classList.add('bg-gray-200', 'text-gray-800');
                    button.textContent = 'Unblock';
                    button.classList.remove('bg-gray-500', 'hover:bg-gray-600');
                    button.classList.add('bg-green-500', 'hover:bg-green-600');
                    button.setAttribute('onclick', `toggleBlockStatus('${username}', 'true')`);
                } else {
                    statusSpan.textContent = 'Active';
                    statusSpan.classList.remove('bg-gray-200', 'text-gray-800');
                    statusSpan.classList.add('bg-green-100', 'text-green-800');
                    button.textContent = 'Block';
                    button.classList.remove('bg-green-500', 'hover:bg-green-600');
                    button.classList.add('bg-gray-500', 'hover:bg-gray-600');
                    button.setAttribute('onclick', `toggleBlockStatus('${username}', 'false')`);
                }

                showMessage("Success", result.message);
            } else {
                showMessage("Error", result.error || "Action failed.");
            }
        }
    </script>
</body>
</html>
"""

# --- HELPER FUNCTIONS AND DECORATORS ---

def requires_login(f):
    """Decorator to check if user is logged in."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def requires_admin(f):
    """Decorator to check if user is logged in AND is an admin."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 1. Check if logged in
        if 'user' not in session:
            return redirect(url_for('index'))
            
        # 2. Check role
        if session.get('user', {}).get('role') != ADMIN_ROLE:
            abort(403) # Forbidden
        return f(*args, **kwargs)
    return decorated_function


# --- ROUTES ---

@app.route('/', methods=['GET'])
def index():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return render_template_string(AUTH_HTML, view='login', error=None)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return render_template_string(AUTH_HTML, view='login', error='Missing credentials.')

    user_data = USER_DB.get(username)

    if user_data:
        # 1. Check if the user is blocked
        if user_data['is_blocked']:
            return render_template_string(AUTH_HTML, view='login', error='Account is blocked. Contact administrator.')

        # 2. Check the secure password hash using the custom function
        if custom_check_password_hash(user_data['password_hash'], password):
            session.permanent = True
            session['user'] = {'username': username, 'role': user_data['role']}
            return redirect(url_for('dashboard'))

    # If user doesn't exist or password check fails
    return render_template_string(AUTH_HTML, view='login', error='Invalid username or password.')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Determine the client's IP address
        # In a real deployed environment, 'X-Forwarded-For' is often used
        # In this environment, request.remote_addr is the most reliable way
        client_ip = request.remote_addr 
        
        # --- IP Registration Limit Check ---
        current_count = IP_REGISTRATION_COUNT.get(client_ip, 0)
        
        if current_count >= MAX_REGISTRATIONS_PER_IP:
            error_msg = f'Registration limit exceeded for this IP address ({client_ip}). Max allowed: {MAX_REGISTRATIONS_PER_IP}'
            print(f"RATE LIMIT: {error_msg}")
            return render_template_string(AUTH_HTML, view='register', error=error_msg)
        # --- End IP Check ---


        if not username or not password:
            return render_template_string(AUTH_HTML, view='register', error='Missing credentials.')

        if username in USER_DB:
            return render_template_string(AUTH_HTML, view='register', error='Username already exists.')

        # If all checks pass, proceed with registration
        
        # 1. Security: Hash the password before saving using the custom function
        hashed_password = custom_generate_password_hash(password)

        # 2. Default registration is always USER_ROLE
        USER_DB[username] = {'password_hash': hashed_password, 'role': USER_ROLE, 'is_blocked': False}
        
        # 3. Update the IP registration count
        IP_REGISTRATION_COUNT[client_ip] = current_count + 1
        print(f"SUCCESSFUL REGISTRATION: User {username} from IP {client_ip}. Total registrations: {IP_REGISTRATION_COUNT[client_ip]}")


        session.permanent = True
        session['user'] = {'username': username, 'role': USER_ROLE}
        return redirect(url_for('dashboard'))
    
    return render_template_string(AUTH_HTML, view='register', error=None)

@app.route('/dashboard')
@requires_login
def dashboard():
    user = session['user']
    username = user['username']
    role = user['role']

    # Mock data for demonstration
    products = [
        {'id': 1, 'name': 'Quantum Flux Capacitor', 'price': 999.99, 'description': 'Enables temporal displacement.'},
        {'id': 2, 'name': 'Invisibility Cloak', 'price': 150.00, 'description': 'Perfect for silent observation.'},
        {'id': 3, 'name': 'Self-Stirring Mug', 'price': 29.50, 'description': 'The lazy person\'s dream.'}
    ]

    # If the user is an admin, they get the full list of users for management
    dashboard_users = USER_DB if role == ADMIN_ROLE else {}

    return render_template_string(
        DASHBOARD_HTML, 
        username=username, 
        role=role, 
        products=products,
        users=dashboard_users
    )

@app.route('/logout')
@requires_login
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))


# --- ADMIN API ENDPOINTS (Secured) ---

@app.route('/api/block_user', methods=['POST'])
@requires_admin
def api_block_user():
    data = request.get_json()
    username = data.get('username')
    is_blocked = data.get('is_blocked')

    if not isinstance(is_blocked, bool):
        return jsonify({'error': 'Field is_blocked must be a boolean.'}), 400

    if username not in USER_DB:
        return jsonify({'error': 'User not found.'}), 404

    # Prevent admin from blocking their own account
    if username == session['user']['username']:
        return jsonify({'error': 'Cannot block your own account.'}), 400

    USER_DB[username]['is_blocked'] = is_blocked
    action = "blocked" if is_blocked else "unblocked"
    
    return jsonify({'message': f'User {username} has been successfully {action}.'})

@app.route('/api/add_admin', methods=['POST'])
@requires_admin
def api_add_admin():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Missing username or password.'}), 400

    if username in USER_DB:
        return jsonify({'error': 'Username already exists.'}), 409

    # Security: Hash the password using the custom function
    hashed_password = custom_generate_password_hash(password)

    # Register as admin
    USER_DB[username] = {'password_hash': hashed_password, 'role': ADMIN_ROLE, 'is_blocked': False}
    return jsonify({'message': f'Admin user {username} created successfully.'})


# --- ENTRY POINT ---
if __name__ == '__main__':
    # Running directly uses Flask's development server.
    # For production (like Render), gunicorn is used (via requirements.txt).
    app.run(debug=True, port=int(os.environ.get('PORT', 5000)))
