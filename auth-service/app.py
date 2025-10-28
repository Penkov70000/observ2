import time
import jwt
import bcrypt
from flask import Flask, request, jsonify
from prometheus_client import generate_latest, Counter, Histogram, REGISTRY
import logging
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.resources import Resource
from opentelemetry.instrumentation.flask import FlaskInstrumentor

# OpenTelemetry setup
resource = Resource(attributes={
    "service.name": "auth-service"
})

trace.set_tracer_provider(TracerProvider(resource=resource))
tracer_provider = trace.get_tracer_provider()
tracer_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))

app = Flask(__name__)
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

# Mock user database
users = [
    {
        "id": 1,
        "username": "admin",
        "password": bcrypt.hashpw("password".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    }
]

JWT_SECRET = "your-secret-key"

@app.before_request
def before_request():
    request.start_time = time.time()

@app.after_request
def after_request(response):
    # Skip metrics endpoint from metrics
    if request.path != '/metrics':
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

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "OK", "service": "auth-service"})

@app.route('/metrics', methods=['GET'])
def metrics():
    return generate_latest(REGISTRY), 200, {'Content-Type': 'text/plain'}

@app.route('/login', methods=['POST'])
def login():
    with tracer_provider.get_tracer(__name__).start_as_current_span("login"):
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
        
        token = jwt.encode(
            {"user_id": user['id'], "username": user['username']},
            JWT_SECRET,
            algorithm="HS256"
        )
        
        return jsonify({
            "token": token,
            "user_id": user['id'],
            "username": user['username']
        })

@app.route('/verify', methods=['POST'])
def verify_token():
    with tracer_provider.get_tracer(__name__).start_as_current_span("verify_token"):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "No token provided"}), 401
        
        token = auth_header.split(' ')[1]
        
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            return jsonify({"valid": True, "user": decoded})
        except jwt.ExpiredSignatureError:
            return jsonify({"valid": False, "error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"valid": False, "error": "Invalid token"}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8081, debug=True)