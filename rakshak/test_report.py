import requests
login_res = requests.post("http://localhost:8000/api/auth/login", json={"username": "admin", "password": "admin@123"})
if not login_res.ok:
    print("Login failed", login_res.status_code, login_res.text)
    exit(1)
token = login_res.json()["access_token"]
response = requests.post(
    "http://localhost:8000/api/reports/generate",
    headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
    json={
        "title": "Test", 
        "format": "pdf", 
        "delivery_channel": "local", 
        "modules": ["cbom", "pqc", "rating", "inventory", "discovery"], 
        "asset_ids": []
    }
)
print("Status:", response.status_code)
print("Response:", response.text)
