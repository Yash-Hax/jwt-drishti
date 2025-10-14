import jwt
import base64, json, time
from jwt import InvalidSignatureError, InvalidTokenError
from .jwks import fetch_jwks, get_key_for_kid

SAFE_ALGS = {
    'RS256', 'RS384', 'RS512',
    'ES256', 'ES384', 'ES512',
    'PS256', 'PS384', 'PS512',
    'HS256', 'HS384', 'HS512',
    'none'
}

def _b64decode_nopad(x: str):
    rem = len(x) % 4
    if rem:
        x += '=' * (4 - rem)
    return base64.urlsafe_b64decode(x.encode('utf-8'))

def _split_token(tok: str):
    parts = tok.split('.')
    if len(parts) < 2:
        raise ValueError('Not a valid JWT (less than 2 parts)')
    return parts

def load_token_from_file(path: str):
    if '\n' in path or len(path) > 4096:
        raise FileNotFoundError()
    with open(path, 'r') as f:
        data = f.read().strip()
        return data

def analyze_token(token: str, verify: bool = False, verification=None):
    result = {'warnings': [], 'claims': {}, 'alg': None, 'rating': 'low'}
    try:
        parts = _split_token(token)
        header_b = _b64decode_nopad(parts[0])
        header = json.loads(header_b)
        result['alg'] = header.get('alg')
    except Exception as e:
        result['warnings'].append(f'Failed to parse header: {e}')
        return result

    if result['alg'] not in SAFE_ALGS:
        result['warnings'].append(f'Unrecognized or custom alg: {result.get("alg")}')
    if result['alg'] == 'none':
        result['warnings'].append('Algorithm is "none" — token is unsigned!')
        result['rating'] = 'high'

    try:
        payload_b = _b64decode_nopad(parts[1])
        payload = json.loads(payload_b)
        result['claims'] = payload
    except Exception as e:
        result['warnings'].append(f'Failed to parse payload: {e}')
        return result

    now = int(time.time())
    exp = payload.get('exp')
    iat = payload.get('iat')
    aud = payload.get('aud')
    iss = payload.get('iss')

    if exp is None:
        result['warnings'].append('Missing exp (no expiry).')
        if result['rating'] != 'high':
            result['rating'] = 'medium'
    else:
        try:
            exp_i = int(exp)
            if exp_i < now:
                result['warnings'].append('Token is expired.')
                result['rating'] = 'high'
            elif exp_i - now < 3600:
                result['warnings'].append('Token expires within 1 hour.')
                if result['rating'] == 'low':
                    result['rating'] = 'medium'
        except Exception:
            result['warnings'].append('Invalid exp format (should be int timestamp).')

    if iat is not None:
        try:
            iat_i = int(iat)
            if iat_i > now + 300:
                result['warnings'].append('Issued-at (iat) is in the future.')
                result['rating'] = 'medium'
        except Exception:
            result['warnings'].append('Invalid iat format.')

    if aud is None:
        result['warnings'].append('Missing aud (audience). Consider validating audience.')
        if result['rating'] == 'low':
            result['rating'] = 'medium'

    if isinstance(result.get('alg'), str) and result['alg'].startswith('HS'):
        kid = header.get('kid')
        if kid and (kid.startswith('-----') or kid.count('.') > 2):
            result['warnings'].append('Possible alg confusion: HS* used while keys look asymmetric.')

    if verify and isinstance(verification, tuple):
        verified, payload_or_err = verification
        result['verification'] = {'verified': bool(verified)}
        if not verified:
            result['warnings'].append(f'Signature verification failed: {payload_or_err}')
            result['rating'] = 'high'

    return result
def verify_with_jwks(token: str, url: str, kid: str|None):
    jwks = fetch_jwks(url)
    keydata = get_key_for_kid(jwks, kid)
    alg = keydata.get("alg") or "RS256"
    try:
        if "n" in keydata and "e" in keydata:  # RSA
            pubkey = RSAAlgorithm.from_jwk(json.dumps(keydata))
        elif "x" in keydata and "y" in keydata:  # EC
            pubkey = ECAlgorithm.from_jwk(json.dumps(keydata))
        else:
            raise ValueError("Unsupported key type in JWKS.")
        payload = jwt.decode(token, pubkey, algorithms=[alg], options={"verify_aud": False})
        return True, payload
    except Exception as e:
        return False, str(e)
        
def verify_token_with_key(token: str, keydata: str):
    try:
        unverified_header = jwt.get_unverified_header(token)
    except Exception as e:
        return False, f'Header parse error: {e}'
    alg = unverified_header.get('alg')
    try:
        if alg and alg.startswith('HS'):
            payload = jwt.decode(token, keydata, algorithms=[alg], options={"verify_aud": False})
            return True, payload
        else:
            payload = jwt.decode(token, keydata, algorithms=[alg], options={"verify_aud": False})
            return True, payload
    except InvalidSignatureError as e:
        return False, f'Invalid signature: {e}'
    except InvalidTokenError as e:
        return False, f'Invalid token: {e}'
    except Exception as e:
        return False, f'Verification error: {e}'

