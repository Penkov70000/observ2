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
from opentelemetry.propagate import inject

# OpenTelemetry setup
resource = Resource(attributes={
    "service.name": "gateway"
})

trace.set_tracer_provider(TracerProvider(resource=resource))
tracer_provider = trace.get_tracer_provider()
tracer_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))

app = Flask(__name__)
FlaskInstrumentor().instrument_app(app)

# Configuration
AUTH_SERVICE_URL = "http://auth-service:8081"
ORDER_SERVICE_URL = "http://order-service:8082"

# Prometheus metrics
gateway_requests_counter = Counter(
    'gateway_requests_total',
    'Total number of gateway requests',
    ['method', 'endpoint', 'status']
)

gateway_request_duration = Histogram(
    'gateway_request_duration_seconds',
    'Duration of gateway requests in seconds',
    ['method', 'endpoint']
)

def make_service_request(service_url, path, method='GET', data=None, headers=None):
    """Make request to backend service"""
    url = f"{service_url}{path}"
    headers = headers or {}
    
    try:
        if method.upper() == 'GET':
            response = requests.get(url, headers=headers, timeout=30)
        elif method.upper() == 'POST':
            response = requests.post(url, json=data, headers=headers, timeout=30)
        else:
            return {"error": "Method not allowed"}, 405
            
        try:
            json_data = response.json()
        except ValueError:
            json_data = {"error": "Invalid JSON response from service"}
            
        return json_data, response.status_code
        
    except requests.exceptions.Timeout:
        return {"error": "Service timeout"}, 504
    except requests.exceptions.ConnectionError:
        return {"error": "Service unavailable"}, 503
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {str(e)}"}, 500

@app.before_request
def before_request():
    request.start_time = time.time()

@app.after_request
def after_request(response):
    if request.path != '/metrics':
        duration = time.time() - request.start_time
        gateway_request_duration.labels(
            method=request.method,
            endpoint=request.path
        ).observe(duration)
        
        gateway_requests_counter.labels(
            method=request.method,
            endpoint=request.path,
            status=response.status_code
        ).inc()
    
    return response

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "OK", "service": "gateway"})

@app.route('/metrics', methods=['GET'])
def metrics():
    return generate_latest(REGISTRY), 200, {'Content-Type': 'text/plain'}

# Auth routes - ИСПРАВЛЕННАЯ ВЕРСИЯ
@app.route('/auth/<path:path>', methods=['POST', 'GET'])
def auth_proxy(path):
    with tracer_provider.get_tracer(__name__).start_as_current_span("auth_proxy"):
        # Создаем заголовки для передачи трассировки
        headers = {}
        inject(headers)  # Автоматически использует текущий контекст
        
        # Копируем оригинальные заголовки (кроме Host)
        for key, value in request.headers:
            if key.lower() != 'host':
                headers[key] = value
        
        # Добавляем Content-Type если его нет
        if request.method == 'POST' and 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/json'
        
        # Логируем для отладки
        print(f"Proxying to auth-service: {request.method} /{path}")
        print(f"Headers: {headers}")
        
        data = request.get_json(silent=True) if request.method == 'POST' else None
        
        response_data, status_code = make_service_request(
            AUTH_SERVICE_URL,
            f'/{path}',
            request.method,
            data,
            headers
        )
        
        return jsonify(response_data), status_code

# Order routes with authentication
@app.route('/orders', methods=['GET', 'POST'])
@app.route('/orders/<path:path>', methods=['GET'])
def orders_proxy(path=None):
    with tracer_provider.get_tracer(__name__).start_as_current_span("orders_proxy"):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        # Verify token
        try:
            auth_response = requests.post(
                f"{AUTH_SERVICE_URL}/verify",
                headers={'Authorization': f'Bearer {token}'},
                timeout=5
            )
            
            if auth_response.status_code != 200:
                return jsonify({"error": "Invalid token"}), 401
                
            auth_data = auth_response.json()
        except requests.exceptions.RequestException as e:
            return jsonify({"error": f"Authentication service unavailable: {str(e)}"}), 503
        
        # Prepare headers for order service
        headers = {}
        inject(headers)  # Трассировка
        
        # Базовые заголовки
        headers['Authorization'] = f'Bearer {token}'
        headers['X-User-Id'] = str(auth_data['user']['user_id'])
        headers['X-Username'] = auth_data['user']['username']
        
        # Content-Type для POST
        if request.method == 'POST':
            headers['Content-Type'] = 'application/json'
        
        data = request.get_json(silent=True) if request.method == 'POST' else None
        
        full_path = f"/{path}" if path else ""
        response_data, status_code = make_service_request(
            ORDER_SERVICE_URL,
            f'/orders{full_path}',
            request.method,
            data,
            headers
        )
        
        return jsonify(response_data), status_code

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)