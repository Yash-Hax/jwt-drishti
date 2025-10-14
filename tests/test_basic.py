from jwt_inspector.analyzer import analyze_token
import jwt, time

def test_decode_simple_hs256():
    secret = 'secret123'
    payload = {'sub':'123','exp': int(time.time())+3600, 'aud':'cli'}
    token = jwt.encode(payload, secret, algorithm='HS256')
    res = analyze_token(token)
    assert 'sub' in res['claims']
    assert res['rating'] in ('low','medium','high')
