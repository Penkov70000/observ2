import requests
import json

def test_all_endpoints():
    base_url_gateway = "http://localhost:8080"
    base_url_auth = "http://localhost:8081"
    
    print("=== Testing All Endpoints ===")
    
    # 1. Test gateway health
    print("1. Testing gateway health...")
    try:
        response = requests.get(f"{base_url_gateway}/health")
        print(f"   SUCCESS Gateway health: {response.status_code}")
        print(f"   Response: {response.json()}")
    except Exception as e:
        print(f"   ERROR Gateway health failed: {e}")
    
    # 2. Test auth health through gateway
    print("\n2. Testing auth health through gateway...")
    try:
        response = requests.get(f"{base_url_gateway}/auth/health")
        print(f"   Auth health via gateway: {response.status_code}")
        if response.status_code == 200:
            print(f"   Response: {response.json()}")
        else:
            print(f"   Response text: {response.text[:200]}")
    except Exception as e:
        print(f"   ERROR Auth health via gateway failed: {e}")
    
    # 3. Test auth health directly
    print("\n3. Testing auth health directly...")
    try:
        response = requests.get(f"{base_url_auth}/health")
        print(f"   Auth health direct: {response.status_code}")
        if response.status_code == 200:
            print(f"   Response: {response.json()}")
        else:
            print(f"   Response text: {response.text[:200]}")
    except Exception as e:
        print(f"   ERROR Auth health direct failed: {e}")
    
    # 4. Test login through gateway with correct path
    print("\n4. Testing login through gateway...")
    try:
        response = requests.post(
            f"{base_url_gateway}/auth/api/login",
            headers={"Content-Type": "application/json"},
            json={"username": "admin", "password": "admin123"}
        )
        print(f"   Login via gateway: {response.status_code}")
        print(f"   Response headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"   SUCCESS Login successful!")
            print(f"   Token: {data.get('token', '')[:50]}...")
        else:
            print(f"   Response: {response.text[:500]}")
            
    except Exception as e:
        print(f"   ERROR Login test failed: {e}")
    
    # 5. Test login directly
    print("\n5. Testing login directly...")
    try:
        response = requests.post(
            f"{base_url_auth}/api/login",
            headers={"Content-Type": "application/json"},
            json={"username": "admin", "password": "admin123"}
        )
        print(f"   Login direct: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   SUCCESS Direct login successful!")
            print(f"   Token: {data.get('token', '')[:50]}...")
        else:
            print(f"   Response: {response.text[:500]}")
    except Exception as e:
        print(f"   ERROR Direct login failed: {e}")

if __name__ == "__main__":
    test_all_endpoints()