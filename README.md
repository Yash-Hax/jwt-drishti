# jwt-drishti

Lightweight JWT analysis and validation CLI.

## Features
- Decode JWTs safely (no verification by default)
- Detect risky algorithms (e.g. `none`, algorithm confusion)
- Check common claims: `exp`, `iat`, `aud`, `iss`
- Optional signature verification with provided key
- JSON output for automation
- Simple security rating and suggestions

## Install (local)
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install .
```

Or use directly:
```bash
pip install -r requirements.txt
python -m jwt_drishti.cli <args>
```

## Usage examples
Decode and analyze (human output):
```bash
jwt-drishti decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Verify with HMAC key:
```bash
jwt-drishti verify --key ./secret.txt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

JSON machine output:
```bash
jwt-drishti decode --json token.txt
```

## Quick dev notes
- This CLI is intentionally conservative (non-destructive).
- Do **not** paste production tokens with real privileges into public tools.
