import requests
from flask import Flask, request, Response, make_response

app = Flask(__name__)

# Client backend
CLIENT_ORIGIN = "https://sherm-cj5m.onrender.com"

# GhostWall API config
GHOSTWALL_API_CHECK_URL = "https://ghostwallapi.onrender.com/check"
GHOSTWALL_API_KEY = "test123"

# Skip detection on these file types
STATIC_EXTENSIONS = ('.js', '.css', '.ico', '.png', '.jpg', '.jpeg', '.svg', '.woff2', '.ttf', '.map')

@app.route('/', defaults={'path': ''}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
@app.route('/<path:path>', methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def proxy(path):
    ip = request.remote_addr
    headers = dict(request.headers)
    cookies = dict(request.cookies)

    # Skip detection if resource is static (e.g. .css or .js)
    if any(path.endswith(ext) for ext in STATIC_EXTENSIONS):
        skip_reason = "skipped: static resource"
        return forward_request(path, skip_reason)

    # Skip detection if user already passed and has cookie
    if cookies.get("gw_seen") == "true":
        skip_reason = "skipped: trusted via cookie"
        return forward_request(path, skip_reason)

    # Build fingerprint data for detection
    data = {
        "api_key": GHOSTWALL_API_KEY,
        "user_agent": headers.get('User-Agent', ''),
        "ip": ip,
        "accept": headers.get('Accept', ''),
        "accept_encoding": headers.get('Accept-Encoding', ''),
        "accept_language": headers.get('Accept-Language', ''),
        "connection": headers.get('Connection', ''),
        "referer": headers.get('Referer', ''),
        "cookies": cookies,
        "headers": headers
    }

    # Send detection request to GhostWall API
    try:
        forwarded = {h: headers[h] for h in ['user-agent', 'accept-language', 'accept', 'referer', 'cookie'] if h in headers}
        resp = requests.post(GHOSTWALL_API_CHECK_URL, json=data, headers=forwarded, timeout=5)
        resp.raise_for_status()
        result = resp.json()
        visitor_type = result.get("result", "human")
    except Exception:
        visitor_type = "human"

    if visitor_type == "bot":
        return Response("Access denied: Bot detected", status=403)

    # If human, set trust cookie for future visits
    response = forward_request(path)
    response.set_cookie("gw_seen", "true", max_age=3600 * 6, httponly=True)
    return response

def forward_request(path, log_reason=None):
    """Forward the current request to the client backend."""
    url = f"{CLIENT_ORIGIN}/{path}"
    forward_headers = {k: v for k, v in request.headers.items() if k.lower() != 'host'}

    proxied_resp = requests.request(
        method=request.method,
        url=url,
        headers=forward_headers,
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False
    )

    excluded_headers = ['content-length', 'transfer-encoding', 'connection']
    headers = [(k, v) for k, v in proxied_resp.headers.items() if k.lower() not in excluded_headers]

    response = make_response(proxied_resp.content, proxied_resp.status_code)
    for name, value in headers:
        response.headers[name] = value

    return response

if __name__ == "__main__":
    app.run(debug=True)
