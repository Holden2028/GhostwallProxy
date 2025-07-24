import requests
from flask import Flask, request, Response

app = Flask(__name__)

# Hardcoded client backend URL
CLIENT_ORIGIN = "https://sherm-cj5m.onrender.com"  # No trailing slash here

# Your GhostWall API bot detection endpoint and API key
GHOSTWALL_API_CHECK_URL = "https://ghostwallapi.onrender.com/check"
GHOSTWALL_API_KEY = "test123"  # Replace with your valid API key


@app.route('/', defaults={'path': ''}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
@app.route('/<path:path>', methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def proxy(path):
    # Prepare JSON body for GhostWall API check
    data = {
        "api_key": GHOSTWALL_API_KEY,
        "user_agent": request.headers.get('User-Agent', '')
    }

    # Prepare headers to forward to GhostWall API detection
    headers_to_forward = {}
    critical_headers = ['user-agent', 'accept-language', 'accept', 'referer', 'cookie']
    for header_name in critical_headers:
        if header_name in request.headers:
            headers_to_forward[header_name] = request.headers[header_name]

    # Call GhostWall API to detect bot with forwarded headers
    try:
        resp = requests.post(
            GHOSTWALL_API_CHECK_URL,
            json=data,
            headers=headers_to_forward,
            timeout=5
        )
        resp.raise_for_status()
        result = resp.json()
        visitor_type = result.get("result", "human")
    except Exception:
        visitor_type = "human"  # Fail open

    if visitor_type == "bot":
        return Response("Access denied: Bot detected", status=403)

    # Forward request to client origin
    url = f"{CLIENT_ORIGIN}/{path}"

    # Forward original headers but exclude 'host' and manage 'accept-encoding' carefully
    forward_headers = {k: v for k, v in request.headers.items() if k.lower() != 'host'}

    # Optionally force backend to return uncompressed data by removing 'accept-encoding'
    # Uncomment the next line if backend compression is causing issues
    # forward_headers.pop('accept-encoding', None)

    proxied_resp = requests.request(
        method=request.method,
        url=url,
        headers=forward_headers,
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False
    )

    # Exclude hop-by-hop headers except 'content-encoding' so browser can decompress
    excluded_headers = ['content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for (name, value) in proxied_resp.headers.items() if name.lower() not in excluded_headers]

    return Response(proxied_resp.content, proxied_resp.status_code, headers)


if __name__ == "__main__":
    app.run(debug=True)
