import time
import jwt
import uuid
import bcrypt
from datetime import datetime
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
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode
from prometheus_client import Gauge, Summary, Histogram, Counter, Info

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
auth_requests_counter = Counter( #  количество HTTP запросо
    'auth_requests_total',
    'Total number of auth requests',
    ['method', 'endpoint', 'status'] #  статус код (200, 401, 500)
)

auth_request_duration = Histogram( #  время выполнения запросов
    'auth_request_duration_seconds',
    'Duration of auth requests in seconds',
    ['method', 'endpoint'], # Лейблы: метод (GET, POST) путь эндпоинта (/login, /register) 
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0]  # Кастомные бакеты
)

# НОВЫЕ МЕТРИКИ
# НОВЫЕ МЕТРИКИ:

# Бизнес-метрики
active_users_gauge = Gauge(
    'auth_active_users',
    'Number of currently active users'
)

user_registrations_counter = Counter(
    'auth_user_registrations_total',
    'Total number of user registrations'
)

failed_logins_counter = Counter(
    'auth_failed_logins_total',
    'Total number of failed login attempts',
    ['reason']  # wrong_password, user_not_found
)

successful_logins_counter = Counter(
    'auth_successful_logins_total',
    'Total number of successful logins'
)

# Системные метрики
jwt_tokens_issued = Counter(
    'auth_jwt_tokens_issued_total',
    'Total number of JWT tokens issued'
)

token_verification_duration = Histogram(
    'auth_token_verification_duration_seconds',
    'Duration of token verification',
    buckets=[0.001, 0.005, 0.01, 0.05, 0.1]
)

password_hashing_duration = Histogram(
    'auth_password_hashing_duration_seconds',
    'Duration of password hashing operations'
)

# Метрики базы данных (in-memory)
database_operations_counter = Counter(
    'auth_database_operations_total',
    'Total number of database operations',
    ['operation']  # create, read, update, delete
)

users_gauge = Gauge(
    'auth_users_total',
    'Total number of registered users'
)

# Информация о сервисе
service_info = Info(
    'auth_service_info',
    'Information about the auth service'
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

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('auth-service')

@app.route('/metrics', methods=['GET'])
def metrics():
    return generate_latest(REGISTRY), 200, {'Content-Type': 'text/plain'}


###########################КАСТОМНОЕ ТРАССИРОВАНИЕ
def login_user_instrumented(username, password):
    tracer = trace.get_tracer(__name__)
    
    with tracer.start_as_current_span("user_login") as span:
        # Добавляем атрибуты к span
        span.set_attribute("user.username", username)
        span.set_attribute("login.attempt_timestamp", datetime.utcnow().isoformat())
        
        try:
            # Поиск пользователя
            with tracer.start_as_current_span("find_user"):
                user = next((u for u in users if u['username'] == username), None)
                span.set_attribute("user.found", user is not None)
            
            if not user:
                span.set_status(Status(StatusCode.ERROR, "User not found"))
                span.set_attribute("login.success", False)
                return None
                
            # Проверка пароля
            with tracer.start_as_current_span("verify_password"):
                start_time = time.time()
                is_valid = bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8'))
                password_duration = time.time() - start_time
                
                span.set_attribute("password.verification_duration", password_duration)
                span.set_attribute("password.valid", is_valid)
            
            if not is_valid:
                span.set_status(Status(StatusCode.ERROR, "Invalid password"))
                span.set_attribute("login.success", False)
                return None
            
            # Создание токена
            with tracer.start_as_current_span("create_jwt_token"):
                token = create_jwt_token(user['id'], user['username'])
                span.set_attribute("jwt.token_created", True)
                span.set_attribute("jwt.user_id", user['id'])
            
            span.set_status(Status(StatusCode.OK))
            span.set_attribute("login.success", True)
            
            # Обновляем метрики
            successful_logins_counter.inc()
            active_users_gauge.inc()
            
            return token
            
        except Exception as e:
            span.set_status(Status(StatusCode.ERROR, str(e)))
            span.record_exception(e)
            raise

def setup_structured_logging():
    """Настройка структурированного логирования"""
    class StructuredFormatter(logging.Formatter):
        def format(self, record):
            log_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'level': record.levelname,
                'logger': record.name,
                'message': record.getMessage(),
                'service': 'auth-service'
            }
            
            # Добавляем дополнительные поля если есть
            if hasattr(record, 'user_id'):
                log_data['user_id'] = record.user_id
            if hasattr(record, 'endpoint'):
                log_data['endpoint'] = record.endpoint
            if hasattr(record, 'duration'):
                log_data['duration'] = record.duration
                
            return json.dumps(log_data)
    
    # Применяем форматтер
    for handler in logging.getLogger().handlers:
        handler.setFormatter(StructuredFormatter())

# Использование структурированных логов
def log_auth_attempt(username, success, duration=None, error=None):
    log_data = {
        'event': 'auth_attempt',
        'username': username,
        'success': success,
        'duration': duration
    }
    
    if error:
        log_data['error'] = str(error)
        
    if success:
        logger.info("Authentication successful", extra=log_data)
    else:
        logger.warning("Authentication failed", extra=log_data)


@app.route('/api/login', methods=['POST'])
@app.route('/api/login', methods=['POST'])
def api_login():
    start_time = time.time()
    request_id = str(uuid.uuid4())
    
    # Логируем начало запроса
    logger.info("Login request started", extra={
        'request_id': request_id,
        'endpoint': '/api/login',
        'method': 'POST'
    })
    
    with tracer_provider.get_tracer(__name__).start_as_current_span("api_login") as span:
        try:
            data = request.get_json()
            span.set_attribute("http.method", "POST")
            span.set_attribute("http.route", "/api/login")
            span.set_attribute("request.id", request_id)
            
            if not data or 'username' not in data or 'password' not in data:
                # Метрики
                auth_requests_counter.labels(method='POST', endpoint='/api/login', status='400').inc()
                # Логи
                logger.warning("Invalid login request", extra={
                    'request_id': request_id,
                    'error': 'missing_credentials'
                })
                # Трассировка
                span.set_status(Status(StatusCode.ERROR, "Missing credentials"))
                return jsonify({"error": "Username and password required"}), 400
            
            username = data['username']
            password = data['password']
            
            span.set_attribute("user.username", username)
            
            # Инструментированный логин
            token = login_user_instrumented(username, password)
            
            duration = time.time() - start_time
            
            if token:
                # Успешный логин
                auth_requests_counter.labels(method='POST', endpoint='/api/login', status='200').inc()
                auth_request_duration.labels(method='POST', endpoint='/api/login').observe(duration)
                
                logger.info("Login successful", extra={
                    'request_id': request_id,
                    'username': username,
                    'duration': duration,
                    'user_id': next((u['id'] for u in users if u['username'] == username), None)
                })
                
                span.set_status(Status(StatusCode.OK))
                
                return jsonify({
                    "token": token,
                    "user_id": next(u['id'] for u in users if u['username'] == username),
                    "username": username,
                    "message": "Login successful"
                })
            else:
                # Неуспешный логин
                auth_requests_counter.labels(method='POST', endpoint='/api/login', status='401').inc()
                failed_logins_counter.labels(reason='invalid_credentials').inc()
                
                logger.warning("Login failed - invalid credentials", extra={
                    'request_id': request_id,
                    'username': username,
                    'duration': duration
                })
                
                span.set_status(Status(StatusCode.ERROR, "Invalid credentials"))
                return jsonify({"error": "Invalid credentials"}), 401
                
        except Exception as e:
            duration = time.time() - start_time
            # Ошибка сервера
            auth_requests_counter.labels(method='POST', endpoint='/api/login', status='500').inc()
            
            logger.error("Login error", extra={
                'request_id': request_id,
                'error': str(e),
                'duration': duration
            })
            
            span.set_status(Status(StatusCode.ERROR, str(e)))
            span.record_exception(e)
            
            return jsonify({"error": "Internal server error"}), 500
# def api_login():
#     with tracer_provider.get_tracer(__name__).start_as_current_span("api_login"):
#         data = request.get_json()
        
#         if not data or 'username' not in data or 'password' not in data:
#             return jsonify({"error": "Username and password required"}), 400
        
#         username = data['username']
#         password = data['password']
        
#         user = next((u for u in users if u['username'] == username), None)
#         if not user:
#             return jsonify({"error": "Invalid credentials"}), 401
        
#         if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
#             return jsonify({"error": "Invalid credentials"}), 401
        
#         token = create_jwt_token(user['id'], user['username'])
        
#         return jsonify({
#             "token": token,
#             "user_id": user['id'],
#             "username": user['username'],
#             "message": "Login successful"
#         })

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