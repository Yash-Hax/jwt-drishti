import os, json, time, hashlib, requests

CACHE_TTL = 300  # seconds
CACHE_DIR = "/tmp"

def _cache_path(url: str):
    h = hashlib.sha256(url.encode()).hexdigest()[:16]
    return os.path.join(CACHE_DIR, f"jwt_drishti_jwks_{h}.json")

def fetch_jwks(url: str):
    if not url.startswith("https://"):
        raise ValueError("JWKS URL must use HTTPS.")
    cache = _cache_path(url)
    now = time.time()
    if os.path.exists(cache):
        mtime = os.path.getmtime(cache)
        if now - mtime < CACHE_TTL:
            with open(cache) as f:
                return json.load(f)
    resp = requests.get(url, timeout=3)
    resp.raise_for_status()
    data = resp.json()
    with open(cache, "w") as f:
        json.dump(data, f)
    return data

def get_key_for_kid(jwks: dict, kid: str|None):
    keys = jwks.get("keys", [])
    if not keys:
        raise ValueError("No keys found in JWKS.")
    if kid:
        for k in keys:
            if k.get("kid") == kid:
                return k
        raise ValueError(f"kid {kid!r} not found in JWKS.")
    if len(keys) == 1:
        return keys[0]
    raise ValueError("Multiple keys in JWKS; specify --kid.")
