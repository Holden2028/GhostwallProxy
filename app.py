import requests
from flask import Flask, request, Response

app = Flask(__name__)

# Hardcoded client backend URL
CLIENT_ORIGIN = "https://client-real-site.com"  # Replace with your actual client site

# Your GhostWall API bot detection endpoint and API key
GHOSTWALL_API_CHECK_URL = "https://ghostwallapi.onrender.com/check"
GHOSTWALL_API_KEY = "test123"  # Replace with your valid API key

@app.route('/', defaults={'path': ''}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
@app.route('/<path:path>', methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def proxy(path):
    # Prepare data for GhostWall API check
    data = {
        "api_key": GHOSTWALL_API_KEY,
        "user_agent": request.headers.get('User-Agent', '')
    }
    # Call GhostWall API to detect bot
    try:
        resp = requests.post(GHOSTWALL_API_CHECK_URL, json=data, timeout=5)
        resp.raise_for_status()
        result = resp.json()
        visitor_type = result.get("result", "human")
    except Exception:
        # Fail open: treat as human if API fails
        visitor_type = "human"

    if visitor_type == "bot":
        return Response("Access denied: Bot detected", status=403)

    # Forward request to client origin
    url = f"{CLIENT_ORIGIN.rstrip('/')}/{path}"
    proxied_resp = requests.request(
        method=request.method,
        url=url,
        headers={k: v for k, v in request.headers.items() if k.lower() != 'host'},
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False
    )

    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for (name, value) in proxied_resp.headers.items() if name.lower() not in excluded_headers]

    return Response(proxied_resp.content, proxied_resp.status_code, headers)

if __name__ == "__main__":
    app.run(debug=True)