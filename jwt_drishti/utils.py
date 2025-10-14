# small helpers (kept minimal for clarity)
def safe_str(s):
    try:
        return str(s)
    except Exception:
        return ''
