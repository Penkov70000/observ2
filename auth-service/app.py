import time
import jwt
import bcrypt
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from prometheus_client import generate_latest, Counter, Histogram, REGISTRY
import logging
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.resources import Resource
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from datetime import datetime, timedelta
import json

# OpenTelemetry setup
resource = Resource(attributes={
    "service.name": "auth-service"
})

trace.set_tracer_provider(TracerProvider(resource=resource))
tracer_provider = trace.get_tracer_provider()
tracer_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Для сессий Flask
FlaskInstrumentor().instrument_app(app)

# Prometheus metrics
auth_requests_counter = Counter(
    'auth_requests_total',
    'Total number of auth requests',
    ['method', 'endpoint', 'status']
)

auth_request_duration = Histogram(
    'auth_request_duration_seconds',
    'Duration of auth requests in seconds',
    ['method', 'endpoint']
)

# In-memory "database"
users = []
user_id_counter = 1

JWT_SECRET = "your-jwt-secret-key"

@app.before_request
def before_request():
    request.start_time = time.time()

@app.after_request
def after_request(response):
    # Skip metrics and static files from metrics
    if request.path != '/metrics' and not request.path.startswith('/static'):
        duration = time.time() - request.start_time
        auth_request_duration.labels(
            method=request.method,
            endpoint=request.path
        ).observe(duration)
        
        auth_requests_counter.labels(
            method=request.method,
            endpoint=request.path,
            status=response.status_code
        ).inc()
    
    return response

# Helper functions
def create_jwt_token(user_id, username):
    """Create JWT token"""
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verify_jwt_token(token):
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def get_current_user():
    """Get current user from session or JWT token"""
    # Check session first (for web UI)
    if 'user_id' in session:
        user = next((u for u in users if u['id'] == session['user_id']), None)
        if user:
            return user
    
    # Check JWT token (for API)
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        payload = verify_jwt_token(token)
        if payload:
            return next((u for u in users if u['id'] == payload['user_id']), None)
    
    return None

# Web UI Routes
@app.route('/')
def index():
    """Welcome page"""
    current_user = get_current_user()
    return render_template('index.html', current_user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    """Login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = next((u for u in users if u['username'] == username), None)
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            # Create session
            session['user_id'] = user['id']
            session['username'] = user['username']
            
            # Create JWT token for API
            token = create_jwt_token(user['id'], user['username'])
            session['jwt_token'] = token
            
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials!', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register_page():
    """Registration page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        
        # Check if user exists
        if any(u['username'] == username for u in users):
            flash('Username already exists!', 'error')
            return render_template('register.html')
        
        # Create new user
        global user_id_counter
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        new_user = {
            'id': user_id_counter,
            'username': username,
            'password': hashed_password,
            'email': email,
            'created_at': datetime.utcnow().isoformat()
        }
        
        users.append(new_user)
        user_id_counter += 1
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login_page'))
    
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    """User dashboard"""
    current_user = get_current_user()
    if not current_user:
        flash('Please login to access dashboard.', 'error')
        return redirect(url_for('login_page'))
    
    return render_template('dashboard.html', current_user=current_user, jwt_token=session.get('jwt_token'))

@app.route('/logout')
def logout():
    """Logout user"""
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

# API Routes
@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        "status": "OK", 
        "service": "auth-service",
        "timestamp": datetime.utcnow().isoformat(),
        "users_count": len(users)
    })

@app.route('/metrics', methods=['GET'])
def metrics():
    return generate_latest(REGISTRY), 200, {'Content-Type': 'text/plain'}

@app.route('/api/login', methods=['POST'])
def api_login():
    with tracer_provider.get_tracer(__name__).start_as_current_span("api_login"):
        data = request.get_json()
        
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({"error": "Username and password required"}), 400
        
        username = data['username']
        password = data['password']
        
        user = next((u for u in users if u['username'] == username), None)
        if not user:
            return jsonify({"error": "Invalid credentials"}), 401
        
        if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            return jsonify({"error": "Invalid credentials"}), 401
        
        token = create_jwt_token(user['id'], user['username'])
        
        return jsonify({
            "token": token,
            "user_id": user['id'],
            "username": user['username'],
            "message": "Login successful"
        })

@app.route('/api/register', methods=['POST'])
def api_register():
    with tracer_provider.get_tracer(__name__).start_as_current_span("api_register"):
        data = request.get_json()
        
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({"error": "Username and password required"}), 400
        
        username = data['username']
        password = data['password']
        email = data.get('email', '')
        
        # Check if user exists
        if any(u['username'] == username for u in users):
            return jsonify({"error": "Username already exists"}), 409
        
        # Create new user
        global user_id_counter
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        new_user = {
            'id': user_id_counter,
            'username': username,
            'password': hashed_password,
            'email': email,
            'created_at': datetime.utcnow().isoformat()
        }
        
        users.append(new_user)
        user_id_counter += 1
        
        return jsonify({
            "message": "User registered successfully",
            "user_id": new_user['id'],
            "username": new_user['username']
        }), 201

@app.route('/api/verify', methods=['POST'])
def api_verify_token():
    with tracer_provider.get_tracer(__name__).start_as_current_span("api_verify_token"):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "No token provided"}), 401
        
        token = auth_header.split(' ')[1]
        payload = verify_jwt_token(token)
        
        if payload:
            user = next((u for u in users if u['id'] == payload['user_id']), None)
            if user:
                return jsonify({
                    "valid": True, 
                    "user": {
                        "user_id": user['id'],
                        "username": user['username']
                    }
                })
        
        return jsonify({"valid": False, "error": "Invalid token"}), 401

@app.route('/api/users', methods=['GET'])
def api_get_users():
    """Get list of users (protected endpoint)"""
    current_user = get_current_user()
    if not current_user:
        return jsonify({"error": "Authentication required"}), 401
    
    # Return basic user info (without passwords)
    users_info = [
        {
            "id": user["id"],
            "username": user["username"],
            "email": user.get("email", ""),
            "created_at": user.get("created_at", "")
        }
        for user in users
    ]
    
    return jsonify({"users": users_info, "total": len(users_info)})

@app.route('/api/profile', methods=['GET'])
def api_get_profile():
    """Get current user profile"""
    current_user = get_current_user()
    if not current_user:
        return jsonify({"error": "Authentication required"}), 401
    
    return jsonify({
        "user": {
            "id": current_user["id"],
            "username": current_user["username"],
            "email": current_user.get("email", ""),
            "created_at": current_user.get("created_at", "")
        }
    })

if __name__ == '__main__':
    # Create a default admin user
    hashed_password = bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    users.append({
        'id': user_id_counter,
        'username': 'admin',
        'password': hashed_password,
        'email': 'admin@example.com',
        'created_at': datetime.utcnow().isoformat()
    })
    user_id_counter += 1
    
    print("Default user created: admin / admin123")
    
    app.run(host='0.0.0.0', port=8081, debug=True)