import uuid
from flask import Flask, request, redirect, url_for, session, render_template_string

# Initialize Flask App
app = Flask(__name__)
# Use a secure secret key for session management
app.config['SECRET_KEY'] = 'a_very_secure_secret_key_that_should_be_stored_in_env_vars'

# --- Mock Database ---
# IMPORTANT: In a real application, replace this dictionary with a proper database
# to ensure data persists after the server restarts (which happens frequently on Render).
USERS = {
    # 'username': {'password': 'hashed_password', 'role': 'user/admin'}
    'admin': {'password': 'adminpassword', 'role': 'admin'}, # For demonstration
    'user1': {'password': 'userpassword', 'role': 'user'}
}
# --- End Mock Database ---

# --- HTML TEMPLATE STRINGS ---

INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Advanced Web App - Auth</title>
    <!-- Load Tailwind CSS via CDN -->
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        /* Custom font import for a modern feel */
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');
        body { font-family: 'Inter', sans-serif; }
    </style>
</head>
<body class="bg-gray-50 flex items-center justify-center min-h-screen p-4">

    <div id="auth-card" class="w-full max-w-md bg-white p-8 md:p-10 rounded-xl shadow-2xl transition-all duration-300">
        <h1 class="text-3xl font-bold text-center mb-6 text-gray-800">
            {% if view == 'login' %}
                Welcome Back
            {% else %}
                Join the Platform
            {% endif %}
        </h1>

        <!-- Error/Success Message Display -->
        {% if error %}
        <div class="p-3 mb-4 text-sm text-red-700 bg-red-100 rounded-lg text-center" role="alert">
            {{ error }}
        </div>
        {% endif %}

        <!-- Login Form -->
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
            Don't have an account? 
            <a href="{{ url_for('register') }}" class="font-medium text-indigo-600 hover:text-indigo-500">
                Register now
            </a>
        </p>
        {% endif %}
        
        <!-- Registration Form -->
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
            <a href="{{ url_for('home') }}" class="font-medium text-green-600 hover:text-green-500">
                Sign in
            </a>
        </p>
        {% endif %}
    </div>

</body>
</html>
"""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ role.capitalize() }} Dashboard | Flask App</title>
    <!-- Load Tailwind CSS via CDN -->
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        /* Custom font for a clean look */
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');
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
                    <span class="text-2xl font-extrabold text-indigo-600">
                        Advanced App ({{ role.capitalize() }})
                    </span>
                </div>
                
                <!-- Search Bar (User & Store Panel Feature) -->
                <div class="flex-1 max-w-lg mx-8 hidden md:block">
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
                    <span class="text-gray-700 font-medium">Hello, {{ username }}!</span>
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
                        Admin Control Panel
                    {% else %}
                        Your User Dashboard
                    {% endif %}
                </h2>
                <p class="mt-2 text-xl text-gray-600">
                    Manage your account and explore the store.
                </p>
            </header>

            <!-- Admin-Specific Content -->
            {% if role == 'admin' %}
            <div class="bg-red-50 p-6 rounded-xl shadow-lg border-l-4 border-red-500 mb-8">
                <h3 class="text-2xl font-semibold text-red-800 mb-4">Critical Admin Actions</h3>
                <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <button class="bg-red-600 text-white p-3 rounded-lg hover:bg-red-700 transition transform hover:scale-[1.02]">Manage Users</button>
                    <button class="bg-red-600 text-white p-3 rounded-lg hover:bg-red-700 transition transform hover:scale-[1.02]">View Reports</button>
                    <button class="bg-red-600 text-white p-3 rounded-lg hover:bg-red-700 transition transform hover:scale-[1.02]">System Health Check</button>
                </div>
            </div>
            {% endif %}

            <!-- User Panel & Store View -->
            <div class="bg-white shadow-xl rounded-xl p-6">
                <h3 class="text-2xl font-semibold text-gray-900 mb-6 border-b pb-2">
                    Store & Products
                </h3>
                
                <div id="product-list" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
                    <!-- Product Cards rendered via Flask loop -->
                    {% for product in products %}
                    <div class="product-card bg-gray-50 p-5 rounded-lg shadow-md hover:shadow-xl transition duration-300 border border-gray-200"
                         data-name="{{ product.name | lower }}">
                        <h4 class="text-xl font-bold text-indigo-700 mb-2">{{ product.name }}</h4>
                        <p class="text-gray-600 mb-3">{{ product.description }}</p>
                        <div class="flex justify-between items-center">
                            <span class="text-2xl font-extrabold text-green-600">${{ "{:,.2f}".format(product.price) }}</span>
                            <button class="bg-indigo-500 text-white px-4 py-2 rounded-lg text-sm hover:bg-indigo-600 transition">
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

    <!-- JavaScript for Search Functionality -->
    <script>
        /**
         * Filters the product cards based on the text entered in the search bar.
         */
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

            // Show 'No Results' message if no products match the filter
            if (!found && filter !== '') {
                noResults.classList.remove('hidden');
            } else {
                noResults.classList.add('hidden');
            }
        }
    </script>
</body>
</html>
"""

# --- FLASK ROUTES ---

@app.route('/')
def home():
    """Renders the main landing page, or redirects to dashboard if logged in."""
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template_string(INDEX_HTML, view='login')

@app.route('/login', methods=['POST'])
def login():
    """Handles user login authentication."""
    username = request.form.get('username')
    password = request.form.get('password')

    if username in USERS and USERS[username]['password'] == password:
        session['username'] = username
        session['role'] = USERS[username]['role']
        return redirect(url_for('dashboard'))

    return render_template_string(INDEX_HTML, view='login', error='Invalid credentials.')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username in USERS:
            return render_template_string(INDEX_HTML, view='register', error='Username already exists.')
        
        # In a real app, hash the password before saving!
        USERS[username] = {'password': password, 'role': 'user'}
        session['username'] = username
        session['role'] = 'user'
        # Database operation: save new user
        # e.g., db.users.insert_one({'username': username, 'password': hash(password), 'role': 'user'})
        return redirect(url_for('dashboard'))

    return render_template_string(INDEX_HTML, view='register')


@app.route('/dashboard')
def dashboard():
    """Renders the user or admin dashboard based on session role."""
    if 'username' not in session:
        return redirect(url_for('home'))

    username = session['username']
    role = session['role']
    
    # Store data (mock products for the store/search functionality)
    products = [
        {'id': 1, 'name': 'Quantum Flux Capacitor', 'price': 999.99, 'description': 'Enables temporal displacement.'},
        {'id': 2, 'name': 'Invisibility Cloak', 'price': 150.00, 'description': 'Perfect for silent observation.'},
        {'id': 3, 'name': 'Self-Stirring Mug', 'price': 29.50, 'description': 'The lazy person\'s dream.'},
        {'id': 4, 'name': 'Anti-Gravity Boots', 'price': 450.00, 'description': 'A gentle lift from reality.'}
    ]

    return render_template_string(DASHBOARD_HTML, 
                                  username=username, 
                                  role=role, 
                                  products=products)


@app.route('/logout')
def logout():
    """Clears the session and redirects to the home page."""
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)
