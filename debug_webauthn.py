import requests
from bs4 import BeautifulSoup

session = requests.Session()

# 1. Get CSRF token
login_url = 'http://localhost:8080/login'
response = session.get(login_url)
soup = BeautifulSoup(response.text, 'html.parser')
csrf_token = soup.find('meta', {'name': '_csrf'})['content']
print(f"CSRF Token: {csrf_token}")

# 2. Try /login/webauthn/options
url1 = 'http://localhost:8080/login/webauthn/options'
headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'X-CSRF-TOKEN': csrf_token
}
data = {'username': 'user'}
print(f"Testing {url1}...")
resp1 = session.post(url1, headers=headers, data=data)
print(f"Status: {resp1.status_code}")
print(f"Response: {resp1.text[:200]}")

# 3. Try /webauthn/authenticate/options
url2 = 'http://localhost:8080/webauthn/authenticate/options'
print(f"Testing {url2}...")
resp2 = session.post(url2, headers=headers, data=data)
print(f"Status: {resp2.status_code}")
print(f"Response: {resp2.text[:200]}")
