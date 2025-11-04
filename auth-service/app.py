# Это микросервис аутентификации
import time # Для замера времени выполнения запросов (метрики)
import jwt # Работа с JSON Web Tokens (подпись и верификация)
import bcrypt # Безопасное хеширование паролей (с солью)
from flask import Flask, request, jsonify # Веб-фреймворк Flask: обработка HTTP-запросов и ответов
from prometheus_client import generate_latest, Counter, Histogram, REGISTRY # Экспорт метрик в формате Prometheus
import logging  # не используется напрямую, подразумевает будущую интеграцию логирования
from opentelemetry import trace # Инструментация для распределённой трассировки (distributed tracing)
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.resources import Resource
from opentelemetry.instrumentation.flask import FlaskInstrumentor

# OpenTelemetry setup
resource = Resource(attributes={ # неизменяемое представление объекта, генерирующего телеметрию в виде атрибутов.
    "service.name": "auth-service" # Создаёт ресурс, который будет прикреплён ко всем спанам (trace spans)
}) # Это будет видно в Jaeger как тег service.name = auth-service

trace.set_tracer_provider(TracerProvider(resource=resource)) 
tracer_provider = trace.get_tracer_provider()
tracer_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
# trace — глобальный модуль OpenTelemetry API
# set_tracer_provider(...) — устанавливает глобальный провайдер, 
# чтобы вызовы вроде trace.get_tracer(...) возвращали Tracer из этого провайдера.
# tracer_provider = trace.get_tracer_provider() - Получает тот самый провайдер, который вы только что установили
# Нужно, чтобы добавить к нему обработчики спанов (span processors)
# TracerProvider — фабрика для создания Tracer’ов (объектов, которые создают спаны).
# resource — метаданные, прикрепляемые ко всем спанам в этом провайдере
# OTLPSpanExporter отправляет спаны по HTTP в OpenTelemetry Collector или напрямую в бэкенд, например Jaeger, если он поддерживает OTLP
# По умолчанию отправляет на http://localhost:4318/v1/traces (HTTP endpoint OTLP)
# Вы можете переопределить: OTLPSpanExporter(endpoint="http://otel-collector:4318/v1/traces")
# BatchSpanProcessor буферизует спаны и отправляет их пакетами — эффективнее
# add_span_processor(...) Регистрирует обработчик в провайдере
# Один провайдер может иметь несколько процессоров (например, один в Jaeger, другой в консоль для дебага)

app = Flask(__name__)
FlaskInstrumentor().instrument_app(app) # Автоматически добавляет спаны вокруг каждого HTTP-запроса к Flask-приложению (включая маршрут, метод, статус и т.д.).
# Это часть auto-instrumentation OpenTelemetry

# Prometheus metrics
auth_requests_counter = Counter( # Counter — монотонно возрастающий счётчик
    'auth_requests_total',
    'Total number of auth requests',
    ['method', 'endpoint', 'status'] # method (GET/POST), endpoint (/login, /verify), status (200, 401 и т.д.)
) # Позволяет строить дашборды: «сколько ошибок 401 на /login?»

auth_request_duration = Histogram( # Histogram — собирает распределение времени выполнения запросов
    'auth_request_duration_seconds',
    'Duration of auth requests in seconds',
    ['method', 'endpoint']
) # Prometheus автоматически создаёт бакеты (например, <0.1s, <0.5s, <1s и т.д.) и считает квантили

# Mock user database - имитация БД - Хранение в памяти — только для демо
users = [
    {
        "id": 1,
        "username": "admin",
        "password": bcrypt.hashpw("password".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    }
]
# Пароль хешируется с помощью bcrypt:
# gensalt() генерирует уникальную соль.
# hashpw() создаёт хеш, включающий соль.
# .decode('utf-8') — чтобы сохранить как строку (а не байты)
# в продакшене: используйте СУБД (PostgreSQL, etc.) и никогда не храните пароли в открытом виде
JWT_SECRET = "your-secret-key" # Секрет для подписи и верификации JWT

# Это декоратор Flask, регистрирующий функцию-хук, 
# которая вызывается перед обработкой любого HTTP-запроса (до любого route-обработчика)
@app.before_request
def before_request():
    request.start_time = time.time()
# request — глобальный контекстный объект Flask (thread-local)
# добавляем атрибут start_time к объекту запроса
# Позже, в after_request, мы используем его для расчёта длительности  

@app.after_request
def after_request(response):
    # Skip metrics endpoint from metrics
    if request.path != '/metrics':
        duration = time.time() - request.start_time
        auth_request_duration.labels( # ОБНОВЛЯЕМ ГИСТОГРАММУ
            method=request.method,
            endpoint=request.path
        ).observe(duration)
        
        auth_requests_counter.labels( # ОБНОВЛЯЕМ СЧЕТЧИК
            method=request.method,
            endpoint=request.path,
            status=response.status_code
        ).inc()
    
    return response

@app.route('/health', methods=['GET']) # Позволяет системам мониторинга проверять, жив ли сервис
def health():
    return jsonify({"status": "OK", "service": "auth-service"})

@app.route('/metrics', methods=['GET']) # Возвращает все метрики в формате Prometheus text-based exposition
def metrics(): # Prometheus будет scrape этот эндпоинт каждые N секунд
    return generate_latest(REGISTRY), 200, {'Content-Type': 'text/plain'}

@app.route('/login', methods=['POST'])
def login():
    with tracer_provider.get_tracer(__name__).start_as_current_span("login"): # Создаёт ручной спан с именем "login" — будет виден в Jaeger как отдельная операция внутри трейса запроса
        data = request.get_json() # Это дополняет auto-instrumentation: теперь есть как общий HTTP-спан, так и бизнес-логика внутри
        
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({"error": "Username and password required"}), 400
        
        username = data['username']
        password = data['password']
        
        user = next((u for u in users if u['username'] == username), None)
        if not user:
            return jsonify({"error": "Invalid credentials"}), 401
        
        if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            return jsonify({"error": "Invalid credentials"}), 401
        
        token = jwt.encode( # Генерация JWT
            {"user_id": user['id'], "username": user['username']}, # Токен содержит полезную нагрузку (claims): user_id, username
            JWT_SECRET,
            algorithm="HS256" # Алгоритм HS256 (HMAC-SHA256) — симметричная подпись
        )
# Проверка JSON и обязательных полей.
# Поиск пользователя по username.
# Сравнение хеша пароля через bcrypt.checkpw() — безопасно, даже против атак по времени
        
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
    # Слушает на всех интерфейсах (0.0.0.0) — важно для Docker/Kubernetes.
    # debug=True — только для разработки! В продакшене отключите.