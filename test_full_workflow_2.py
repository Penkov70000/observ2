import requests
import json

def test_order_fix():
    print("=== Testing Order Service Fix ===")
    
    # 1. Получаем токен
    print("\n1. Getting token...")
    login_response = requests.post(
        "http://localhost:8080/auth/api/login",
        json={"username": "admin", "password": "admin123"}
    )
    
    if login_response.status_code != 200:
        print("❌ Login failed")
        return
        
    token = login_response.json()['token']
    print(f"✅ Token: {token[:30]}...")
    
    # 2. Пробуем создать заказ
    print("\n2. Creating order...")
    order_response = requests.post(
        "http://localhost:8080/orders",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        },
        json={"items": ["laptop", "mouse"], "total": 1500.50}
    )
    
    print(f"Order response: {order_response.status_code}")
    if order_response.status_code == 201:
        print("✅ SUCCESS! Order created")
        print(f"Order: {order_response.json()}")
    else:
        print(f"❌ Order failed: {order_response.text}")

if __name__ == "__main__":
    test_order_fix()