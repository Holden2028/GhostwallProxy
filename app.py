import requests
from flask import Flask, request, redirect, Response

app = Flask(__name__)

# Client backend
CLIENT_ORIGIN = "https://sherm-cj5m.onrender.com"

# GhostWall API config
GHOSTWALL_API_CHECK_URL = "https://ghostwallapi.onrender.com/check"
GHOSTWALL_API_KEY = "test123"

@app.route('/', defaults={'path': ''}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
@app.route('/<path:path>', methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def gatekeeper(path):
    ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    headers = dict(request.headers)

    data = {
        "api_key": GHOSTWALL_API_KEY,
        "user_agent": headers.get('User-Agent', ''),
        "ip": ip,
        "accept": headers.get('Accept', ''),
        "accept_encoding": headers.get('Accept-Encoding', ''),
        "accept_language": headers.get('Accept-Language', ''),
        "connection": headers.get('Connection', ''),
        "referer": headers.get('Referer', ''),
        "cookies": dict(request.cookies),
        "headers": headers
    }

    try:
        resp = requests.post(GHOSTWALL_API_CHECK_URL, json=data, timeout=5)
        resp.raise_for_status()
        result = resp.json()
        visitor_type = result.get("result", "human")
    except Exception:
        visitor_type = "human"

    if visitor_type == "bot":
        return Response("Access denied: Bot detected", status=403)

    # Redirect human user to actual site (preserves ad revenue)
    return redirect(f"{CLIENT_ORIGIN}/{path}", code=302)

if __name__ == "__main__":
    app.run(debug=True)
