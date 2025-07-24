import requests
from flask import Flask, request, Response

app = Flask(__name__)

# Client backend
CLIENT_ORIGIN = "https://sherm-cj5m.onrender.com"

# GhostWall API config
GHOSTWALL_API_CHECK_URL = "https://ghostwallapi.onrender.com/check"
GHOSTWALL_API_KEY = "test123"

@app.route('/', defaults={'path': ''}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
@app.route('/<path:path>', methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def proxy(path):
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

    critical_headers = ['user-agent', 'accept-language', 'accept', 'referer', 'cookie']
    headers_to_forward = {h: headers[h] for h in critical_headers if h in headers}

    try:
        resp = requests.post(GHOSTWALL_API_CHECK_URL, json=data, headers=headers_to_forward, timeout=5)
        resp.raise_for_status()
        result = resp.json()
        visitor_type = result.get("result", "human")
    except Exception:
        visitor_type = "human"

    if visitor_type == "bot":
        return Response("Access denied: Bot detected", status=403)

    url = f"{CLIENT_ORIGIN}/{path}"
    forward_headers = {k: v for k, v in headers.items() if k.lower() != 'host'}

    proxied_resp = requests.request(
        method=request.method,
        url=url,
        headers=forward_headers,
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False
    )

    excluded_headers = ['content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for (name, value) in proxied_resp.headers.items() if name.lower() not in excluded_headers]

    return Response(proxied_resp.content, proxied_resp.status_code, headers)

if __name__ == "__main__":
    app.run(debug=True)