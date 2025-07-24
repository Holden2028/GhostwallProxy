import requests
from flask import Flask, request, Response
import re

app = Flask(__name__)

# Hardcoded client backend URL
CLIENT_ORIGIN = "https://sherm-cj5m.onrender.com"

# GhostWall API config
GHOSTWALL_API_CHECK_URL = "https://ghostwallapi.onrender.com/check"
GHOSTWALL_API_KEY = "test123"

# Track JS-executing IPs
executed_js_ips = set()

@app.route("/js-challenge", methods=["POST"])
def js_challenge():
    ip = request.remote_addr
    executed_js_ips.add(ip)
    return '', 204

@app.route('/', defaults={'path': ''}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
@app.route('/<path:path>', methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def proxy(path):
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')

    # Build detection payload
    data = {
        "api_key": GHOSTWALL_API_KEY,
        "user_agent": user_agent,
        "ip": ip,
        "js_passed": ip in executed_js_ips
    }

    # Forward a few important headers
    critical_headers = ['user-agent', 'accept-language', 'accept', 'referer', 'cookie']
    headers_to_forward = {h: request.headers[h] for h in critical_headers if h in request.headers}

    # Call GhostWall API
    try:
        resp = requests.post(GHOSTWALL_API_CHECK_URL, json=data, headers=headers_to_forward, timeout=5)
        resp.raise_for_status()
        visitor_type = resp.json().get("result", "human")
    except Exception:
        visitor_type = "human"

    if visitor_type == "bot":
        return Response("Access denied: Bot detected", status=403)

    # Build the proxied request
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

    # Inject JS if response is HTML
    content_type = proxied_resp.headers.get("Content-Type", "")
    content = proxied_resp.content
    if "text/html" in content_type.lower():
        try:
            html = content.decode("utf-8")
            injection = '''
            <script>
              fetch("/js-challenge", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ passed: true })
              });
            </script>
            '''
            if "</body>" in html:
                html = html.replace("</body>", injection + "</body>")
            else:
                html += injection
            content = html.encode("utf-8")
        except Exception:
            pass  # If decoding fails, skip injection

    excluded_headers = ['content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for (name, value) in proxied_resp.headers.items() if name.lower() not in excluded_headers]

    return Response(content, proxied_resp.status_code, headers)


if __name__ == "__main__":
    app.run(debug=True)