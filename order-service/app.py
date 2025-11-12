import time
import requests
from flask import Flask, request, jsonify
from prometheus_client import generate_latest, Counter, Histogram, REGISTRY
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.resources import Resource
from opentelemetry.instrumentation.flask import FlaskInstrumentor

# OpenTelemetry setup
resource = Resource(attributes={
    "service.name": "order-service"
})

trace.set_tracer_provider(TracerProvider(resource=resource))
tracer_provider = trace.get_tracer_provider()
tracer_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))

app = Flask(__name__)
FlaskInstrumentor().instrument_app(app)

# Configuration - ИСПРАВЛЕННЫЙ URL
AUTH_SERVICE_URL = "http://auth-service:8081"

# Prometheus metrics
order_requests_counter = Counter(
    'order_requests_total',
    'Total number of order requests',
    ['method', 'endpoint', 'status']
)

order_request_duration = Histogram(
    'order_request_duration_seconds',
    'Duration of order requests in seconds',
    ['method', 'endpoint']
)

# Mock database
orders = []
order_id_counter = 1

def authenticate_token(token):
    """Verify token with auth service with debugging"""
    if not token:
        print("❌ No token provided")
        return False, None
        
    print(f"🔐 Authenticating token: {token[:20]}...")
    
    # ИСПРАВЛЕННЫЙ URL - добавляем /api
    auth_url = f"{AUTH_SERVICE_URL}/api/verify"  # ← ВАЖНО: добавили /api
    print(f"🔐 Making request to: {auth_url}")
    
    try:
        response = requests.post(
            auth_url,
            headers={
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'  # ← Добавляем Content-Type
            },
            timeout=5
        )
        
        print(f"🔐 Auth service response: {response.status_code}")
        print(f"🔐 Response headers: {dict(response.headers)}")
        print(f"🔐 Response text: {response.text}")
        
        if response.status_code == 200:
            auth_data = response.json()
            print(f"✅ Token valid: {auth_data}")
            return True, auth_data
        else:
            print(f"❌ Token invalid. Status: {response.status_code}")
            return False, None
            
    except requests.exceptions.Timeout:
        print("❌ Auth service timeout")
        return False, None
    except requests.exceptions.ConnectionError as e:
        print(f"❌ Cannot connect to auth service at {auth_url}")
        print(f"❌ Connection error: {e}")
        return False, None
    except requests.exceptions.RequestException as e:
        print(f"❌ Auth service error: {e}")
        return False, None
    except Exception as e:
        print(f"❌ Unexpected error in authenticate_token: {e}")
        return False, None

@app.before_request
def before_request():
    request.start_time = time.time()

@app.after_request
def after_request(response):
    if request.path != '/metrics':
        duration = time.time() - request.start_time
        order_request_duration.labels(
            method=request.method,
            endpoint=request.path
        ).observe(duration)
        
        order_requests_counter.labels(
            method=request.method,
            endpoint=request.path,
            status=response.status_code
        ).inc()
    
    return response

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "OK", "service": "order-service"})

@app.route('/metrics', methods=['GET'])
def metrics():
    return generate_latest(REGISTRY), 200, {'Content-Type': 'text/plain'}

@app.route('/orders', methods=['GET'])
def get_orders():
    with tracer_provider.get_tracer(__name__).start_as_current_span("get_orders"):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        is_valid, auth_data = authenticate_token(token)
        if not is_valid:
            return jsonify({"error": "Invalid token"}), 401
        
        user_id = auth_data['user']['user_id']
        user_orders = [order for order in orders if order['user_id'] == user_id]
        
        return jsonify(user_orders)

@app.route('/orders', methods=['POST'])
def create_order():
    with tracer_provider.get_tracer(__name__).start_as_current_span("create_order"):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        is_valid, auth_data = authenticate_token(token)
        if not is_valid:
            return jsonify({"error": "Invalid token"}), 401
        
        data = request.get_json()
        if not data or 'items' not in data or 'total' not in data:
            return jsonify({"error": "Items and total are required"}), 400
        
        global order_id_counter
        new_order = {
            'id': order_id_counter,
            'user_id': auth_data['user']['user_id'],
            'items': data['items'],
            'total': data['total'],
            'status': 'pending',
            'created_at': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        orders.append(new_order)
        order_id_counter += 1
        
        return jsonify(new_order), 201

@app.route('/orders/<int:order_id>', methods=['GET'])
def get_order(order_id):
    with tracer_provider.get_tracer(__name__).start_as_current_span("get_order"):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        is_valid, auth_data = authenticate_token(token)
        if not is_valid:
            return jsonify({"error": "Invalid token"}), 401
        
        user_id = auth_data['user']['user_id']
        order = next(
            (order for order in orders if order['id'] == order_id and order['user_id'] == user_id),
            None
        )
        
        if not order:
            return jsonify({"error": "Order not found"}), 404
        
        return jsonify(order)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8082, debug=True)