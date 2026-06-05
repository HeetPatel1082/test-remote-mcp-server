from datetime import date as date_cls, datetime, timezone, timedelta
import json
import os
import secrets
from pathlib import Path
from urllib.parse import quote as url_quote

import bcrypt
import jwt
import libsql_experimental as libsql
from fastmcp import FastMCP
from fastmcp.server.dependencies import get_http_request
from fastapi import FastAPI, Request, Form
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse

# ── Config ────────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
CATEGORIES_PATH = BASE_DIR / "categories.json"

DB_URL           = os.environ.get("TURSO_DATABASE_URL", f"file:{BASE_DIR / 'expenses.db'}")
DB_TOKEN         = os.environ.get("TURSO_AUTH_TOKEN", "")
JWT_SECRET       = os.environ.get("JWT_SECRET", "change-me-in-production-please")
JWT_EXPIRY_HOURS = int(os.environ.get("JWT_EXPIRY_HOURS", "72"))
BASE_URL         = os.environ.get("MCP_BASE_URL", "https://heet-expenses-mcp.onrender.com")

mcp = FastMCP("ExpenseTracker", auth=None)

# ── DB helpers ────────────────────────────────────────────────────────────────
def get_conn():
    return libsql.connect(database=DB_URL, auth_token=DB_TOKEN)

def ex(conn, sql, params=None):
    if params is None:
        return conn.execute(sql)
    return conn.execute(sql, tuple(params))

def rows_to_dicts(cursor):
    cols = [desc[0] for desc in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]

# ── Categories ────────────────────────────────────────────────────────────────
def load_categories():
    if not CATEGORIES_PATH.exists():
        return {"Food": ["Groceries", "Dining"], "Other": []}
    with open(CATEGORIES_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

# ── Validation ────────────────────────────────────────────────────────────────
def validate_iso_date(value):
    date_cls.fromisoformat(value)
    return value

def validate_amount(value):
    amount = float(value)
    if amount == 0:
        raise ValueError("amount must be non-zero")
    return amount

def validate_category(category, subcategory=""):
    categories = load_categories()
    if category not in categories:
        raise ValueError(f"Unknown category: {category}")
    if subcategory and subcategory not in categories[category]:
        raise ValueError(f"Unknown subcategory '{subcategory}' for category '{category}'")

# ── Auth helpers ──────────────────────────────────────────────────────────────
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

def generate_api_key() -> str:
    return "ek_" + secrets.token_hex(32)

def generate_jwt(user_id: int, username: str, days: int = None, hours: int = None) -> str:
    expiry = timedelta(days=days) if days is not None else timedelta(hours=hours or JWT_EXPIRY_HOURS)
    payload = {
        "sub": str(user_id),  # PyJWT v3 requires sub to be a string
        "username": username,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + expiry,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def parse_utc(iso_str: str) -> datetime:
    """Parse ISO datetime string, always returning a timezone-aware UTC datetime."""
    dt = datetime.fromisoformat(iso_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt

def resolve_user(api_key: str = None, token: str = None) -> dict:
    """Resolve user from api_key or JWT token.
    Automatically extracts Bearer token from Authorization header if neither is provided.
    """
    if not api_key and not token:
        try:
            request = get_http_request()
            auth_header = request.headers.get("authorization", "")
            if auth_header.lower().startswith("bearer "):
                token = auth_header[7:].strip()
        except Exception:
            pass

    if not api_key and not token:
        raise ValueError("Authentication required: provide api_key or token")

    conn = get_conn()

    if api_key:
        cur = ex(conn, "SELECT id, username, email FROM users WHERE api_key = ? AND is_active = 1", [api_key])
        rows = rows_to_dicts(cur)
        if not rows:
            raise ValueError("Invalid or inactive API key")
        return rows[0]

    if token:
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            raise ValueError("Token expired — please login again")
        except jwt.InvalidTokenError:
            raise ValueError("Invalid token")
        except Exception as e:
            raise ValueError(f"Token validation failed: {e}")

        cur = ex(conn, "SELECT id, username, email FROM users WHERE id = ? AND is_active = 1", [int(payload["sub"])])
        rows = rows_to_dicts(cur)
        if not rows:
            raise ValueError("User not found or inactive")
        return rows[0]

    raise ValueError("Authentication failed")

# ── DB Init ───────────────────────────────────────────────────────────────────
def init_db():
    try:
        conn = get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                username   TEXT NOT NULL UNIQUE,
                email      TEXT NOT NULL UNIQUE,
                password   TEXT NOT NULL,
                api_key    TEXT NOT NULL UNIQUE,
                is_active  INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_api_key ON users(api_key)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS expenses (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER NOT NULL,
                date        TEXT NOT NULL,
                amount      REAL NOT NULL,
                category    TEXT NOT NULL,
                subcategory TEXT DEFAULT '',
                note        TEXT DEFAULT '',
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_expenses_user_date ON expenses(user_id, date)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_expenses_user_cat  ON expenses(user_id, category)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS oauth_codes (
                code         TEXT PRIMARY KEY,
                user_id      INTEGER NOT NULL,
                redirect_uri TEXT NOT NULL,
                expires_at   TEXT NOT NULL,
                used         INTEGER NOT NULL DEFAULT 0
            )
        """)
        conn.commit()
        print("Database initialized successfully")
    except Exception as e:
        print(f"Database initialization skipped or failed: {e}")

init_db()

# ── MCP Tools ─────────────────────────────────────────────────────────────────

@mcp.tool()
def get_profile(api_key: str = None, token: str = None):
    """Get the currently authenticated user's profile."""
    user = resolve_user(api_key, token)
    return {"status": "ok", "user": user}

@mcp.tool()
def add_expense(date: str, amount, category: str, subcategory: str = "", note: str = "",
                api_key: str = None, token: str = None):
    """Add a new expense entry for the authenticated user."""
    user = resolve_user(api_key, token)
    date   = validate_iso_date(date)
    amount = validate_amount(amount)
    validate_category(category, subcategory)

    conn = get_conn()
    cur = ex(conn,
        "INSERT INTO expenses(user_id, date, amount, category, subcategory, note) VALUES (?,?,?,?,?,?)",
        [user["id"], date, amount, category, subcategory, note]
    )
    conn.commit()
    return {"status": "ok", "id": cur.lastrowid}

@mcp.tool()
def list_expenses(start_date: str, end_date: str, api_key: str = None, token: str = None):
    """List expense entries within an inclusive date range for the authenticated user."""
    user = resolve_user(api_key, token)
    start_date = validate_iso_date(start_date)
    end_date   = validate_iso_date(end_date)

    conn = get_conn()
    cur = ex(conn,
        """
        SELECT id, date, amount, category, subcategory, note
        FROM expenses
        WHERE user_id = ? AND date BETWEEN ? AND ?
        ORDER BY date ASC, id ASC
        """,
        [user["id"], start_date, end_date]
    )
    return rows_to_dicts(cur)

@mcp.tool()
def get_expense(expense_id: int, api_key: str = None, token: str = None):
    """Get a single expense entry by ID (must belong to authenticated user)."""
    user = resolve_user(api_key, token)

    conn = get_conn()
    cur = ex(conn,
        "SELECT id, date, amount, category, subcategory, note FROM expenses WHERE id = ? AND user_id = ?",
        [expense_id, user["id"]]
    )
    rows = rows_to_dicts(cur)
    if not rows:
        return {"found": False}
    return {"found": True, "expense": rows[0]}

@mcp.tool()
def update_expense(expense_id: int, date: str = None, amount=None, category: str = None,
                   subcategory: str = None, note: str = None,
                   api_key: str = None, token: str = None):
    """Update fields on an existing expense (must belong to authenticated user)."""
    user = resolve_user(api_key, token)

    conn = get_conn()
    cur = ex(conn, "SELECT id, category FROM expenses WHERE id = ? AND user_id = ?", [expense_id, user["id"]])
    rows = rows_to_dicts(cur)
    if not rows:
        return {"status": "not_found"}

    current_category = rows[0]["category"]
    updates, params = [], []

    if date is not None:
        updates.append("date = ?"); params.append(validate_iso_date(date))
    if amount is not None:
        updates.append("amount = ?"); params.append(validate_amount(amount))
    if category is not None:
        validate_category(category, subcategory or "")
        updates.append("category = ?"); params.append(category)
    if subcategory is not None:
        effective_cat = category if category is not None else current_category
        validate_category(effective_cat, subcategory)
        updates.append("subcategory = ?"); params.append(subcategory)
    if note is not None:
        updates.append("note = ?"); params.append(note)

    if not updates:
        return {"status": "noop"}

    params.extend([expense_id, user["id"]])
    ex(conn, f"UPDATE expenses SET {', '.join(updates)} WHERE id = ? AND user_id = ?", params)
    conn.commit()
    return {"status": "ok"}

@mcp.tool()
def delete_expense(expense_id: int, api_key: str = None, token: str = None):
    """Delete an expense entry (must belong to authenticated user)."""
    user = resolve_user(api_key, token)

    conn = get_conn()
    cur = ex(conn, "SELECT id FROM expenses WHERE id = ? AND user_id = ?", [expense_id, user["id"]])
    if not cur.fetchone():
        return {"status": "not_found"}

    ex(conn, "DELETE FROM expenses WHERE id = ? AND user_id = ?", [expense_id, user["id"]])
    conn.commit()
    return {"status": "ok"}

@mcp.tool()
def summarize(start_date: str, end_date: str, category: str = None,
              api_key: str = None, token: str = None):
    """Summarize expenses by category within a date range for the authenticated user."""
    user = resolve_user(api_key, token)
    start_date = validate_iso_date(start_date)
    end_date   = validate_iso_date(end_date)
    if category:
        validate_category(category)

    conn   = get_conn()
    query  = "SELECT category, SUM(amount) AS total_amount FROM expenses WHERE user_id = ? AND date BETWEEN ? AND ?"
    params = [user["id"], start_date, end_date]
    if category:
        query += " AND category = ?"; params.append(category)
    query += " GROUP BY category ORDER BY total_amount DESC"

    cur = ex(conn, query, params)
    return rows_to_dicts(cur)

@mcp.tool()
def monthly_summary(year: int, month: int, api_key: str = None, token: str = None):
    """Summarize expenses for a specific month for the authenticated user."""
    user = resolve_user(api_key, token)
    year  = int(year)
    month = int(month)
    if month < 1 or month > 12:
        raise ValueError("month must be between 1 and 12")

    start_date = f"{year:04d}-{month:02d}-01"
    end_date   = f"{year + 1:04d}-01-01" if month == 12 else f"{year:04d}-{month + 1:02d}-01"

    conn = get_conn()
    cur = ex(conn,
        """
        SELECT category, SUM(amount) AS total_amount, COUNT(*) AS expense_count
        FROM expenses
        WHERE user_id = ? AND date >= ? AND date < ?
        GROUP BY category
        ORDER BY total_amount DESC
        """,
        [user["id"], start_date, end_date]
    )
    return rows_to_dicts(cur)

@mcp.tool()
def list_categories():
    """Return the full category and subcategory catalog."""
    return load_categories()

@mcp.resource("expense://categories", mime_type="application/json")
def categories():
    return json.dumps(load_categories(), indent=2)

# ── Shared HTML helpers ───────────────────────────────────────────────────────
_BASE_STYLES = """
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      min-height: 100vh; display: flex; align-items: center; justify-content: center;
      background: #0f0f13;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      color: #e2e8f0;
    }
    .card {
      background: #1a1a24; border: 1px solid #2d2d3d; border-radius: 16px;
      padding: 40px; width: 100%; max-width: 420px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.4);
    }
    .logo { font-size: 28px; margin-bottom: 6px; text-align: center; }
    h1 { font-size: 20px; font-weight: 600; text-align: center; margin-bottom: 6px; color: #f1f5f9; }
    .subtitle { text-align: center; font-size: 13px; color: #64748b; margin-bottom: 28px; }
    label { display: block; font-size: 13px; font-weight: 500; color: #94a3b8; margin-bottom: 6px; }
    input {
      width: 100%; padding: 11px 14px; background: #0f0f13; border: 1px solid #2d2d3d;
      border-radius: 8px; color: #f1f5f9; font-size: 14px; margin-bottom: 18px;
      outline: none; transition: border-color 0.2s;
    }
    input:focus { border-color: #6366f1; }
    .btn {
      width: 100%; padding: 12px; background: #6366f1; color: #fff; border: none;
      border-radius: 8px; font-size: 15px; font-weight: 600; cursor: pointer;
      transition: background 0.2s;
    }
    .btn:hover { background: #4f46e5; }
    .btn-secondary {
      width: 100%; padding: 11px; background: transparent; color: #94a3b8;
      border: 1px solid #2d2d3d; border-radius: 8px; font-size: 14px; cursor: pointer;
      transition: all 0.2s; margin-top: 10px; text-align: center;
      text-decoration: none; display: block;
    }
    .btn-secondary:hover { border-color: #6366f1; color: #a5b4fc; }
    .alert { border-radius: 8px; padding: 10px 14px; font-size: 13px; margin-bottom: 18px; }
    .alert-error { background: #3f1515; border: 1px solid #7f1d1d; color: #fca5a5; }
    .alert-success { background: #14291a; border: 1px solid #166534; color: #86efac; }
    .divider { text-align: center; color: #334155; font-size: 12px; margin: 16px 0; }
    .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #334155; }
"""

def _html_shell(title: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
  <style>{_BASE_STYLES}</style>
</head>
<body>{body}</body>
</html>"""

def _esc(value: str) -> str:
    """HTML-escape a value for safe use inside attribute quotes."""
    return value.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;")

# ── Login page ────────────────────────────────────────────────────────────────
def _login_page(redirect_uri: str, state: str, error: str = "", success: str = "") -> str:
    alert = ""
    if error:
        alert = f'<div class="alert alert-error">{error}</div>'
    elif success:
        alert = f'<div class="alert alert-success">{success}</div>'

    safe_redirect = url_quote(redirect_uri, safe="")
    safe_state    = url_quote(state, safe="")

    body = f"""
  <div class="card">
    <div class="logo">💸</div>
    <h1>Expense Tracker</h1>
    <p class="subtitle">Sign in to connect with Claude</p>
    {alert}
    <form method="POST" action="/login">
      <input type="hidden" name="redirect_uri" value="{_esc(redirect_uri)}">
      <input type="hidden" name="state" value="{_esc(state)}">
      <label for="email">Email</label>
      <input type="email" id="email" name="email" placeholder="you@example.com" required autofocus>
      <label for="password">Password</label>
      <input type="password" id="password" name="password" placeholder="••••••••" required>
      <button type="submit" class="btn">Sign In</button>
    </form>
    <div class="divider">— or —</div>
    <a href="/signup?redirect_uri={safe_redirect}&state={safe_state}" class="btn-secondary">
      Create an account
    </a>
    <p class="footer">Your data stays private — this only authorizes Claude to access your expenses.</p>
  </div>"""
    return _html_shell("Expense Tracker — Sign In", body)

# ── Sign-up page ──────────────────────────────────────────────────────────────
def _signup_page(redirect_uri: str, state: str, error: str = "",
                 prefill_email: str = "", prefill_username: str = "") -> str:
    alert = f'<div class="alert alert-error">{error}</div>' if error else ""
    safe_redirect = url_quote(redirect_uri, safe="")
    safe_state    = url_quote(state, safe="")

    body = f"""
  <div class="card">
    <div class="logo">💸</div>
    <h1>Create Account</h1>
    <p class="subtitle">Set up your Expense Tracker account</p>
    {alert}
    <form method="POST" action="/signup">
      <input type="hidden" name="redirect_uri" value="{_esc(redirect_uri)}">
      <input type="hidden" name="state" value="{_esc(state)}">
      <label for="username">Username</label>
      <input type="text" id="username" name="username" placeholder="yourname"
             value="{_esc(prefill_username)}" required autofocus>
      <label for="email">Email</label>
      <input type="email" id="email" name="email" placeholder="you@example.com"
             value="{_esc(prefill_email)}" required>
      <label for="password">Password</label>
      <input type="password" id="password" name="password" placeholder="Min. 8 characters" required>
      <label for="confirm">Confirm Password</label>
      <input type="password" id="confirm" name="confirm" placeholder="Repeat password" required>
      <button type="submit" class="btn">Create Account</button>
    </form>
    <div class="divider">— or —</div>
    <a href="/login?redirect_uri={safe_redirect}&state={safe_state}" class="btn-secondary">
      Already have an account? Sign in
    </a>
    <p class="footer">Your data stays private — this only authorizes Claude to access your expenses.</p>
  </div>"""
    return _html_shell("Expense Tracker — Create Account", body)

# ── OAuth helpers ─────────────────────────────────────────────────────────────
def _create_oauth_code(conn, user_id: int, redirect_uri: str) -> str:
    code = secrets.token_urlsafe(32)
    expires_at = (now_utc() + timedelta(minutes=10)).isoformat()
    ex(conn,
        "INSERT INTO oauth_codes(code, user_id, redirect_uri, expires_at) VALUES (?,?,?,?)",
        [code, user_id, redirect_uri, expires_at]
    )
    conn.commit()
    return code

def _redirect_with_code(redirect_uri: str, code: str, state: str) -> RedirectResponse:
    separator = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(
        url=f"{redirect_uri}{separator}code={code}&state={state}",
        status_code=302
    )

# ── OAuth & web auth routes ───────────────────────────────────────────────────
def _attach_oauth_routes(fastapi_app: FastAPI):

    @fastapi_app.get("/.well-known/oauth-protected-resource")
    @fastapi_app.get("/.well-known/oauth-protected-resource/mcp")
    async def oauth_protected_resource():
        return JSONResponse({
            "resource": BASE_URL,
            "authorization_servers": [BASE_URL],
            "bearer_methods_supported": ["header"],
            "resource_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["expenses:read", "expenses:write"],
        })

    @fastapi_app.get("/.well-known/oauth-authorization-server")
    async def oauth_authorization_server():
        return JSONResponse({
            "issuer": BASE_URL,
            "authorization_endpoint": f"{BASE_URL}/authorize",
            "token_endpoint": f"{BASE_URL}/token",
            "registration_endpoint": f"{BASE_URL}/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "code_challenge_methods_supported": ["S256"],
        })

    # Claude's OAuth client registration handshake (NOT user signup)
    @fastapi_app.post("/register")
    async def register_oauth_client(request: Request):
        body = await request.json()
        return JSONResponse({
            "client_id": "claude-client-" + secrets.token_hex(8),
            "client_secret": "not-a-real-secret",
            "redirect_uris": body.get("redirect_uris", []),
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_post",
        })

    @fastapi_app.get("/authorize")
    async def authorize(
        redirect_uri: str = "", state: str = "", response_type: str = "code",
        client_id: str = "", code_challenge: str = "", code_challenge_method: str = "",
    ):
        return HTMLResponse(_login_page(redirect_uri, state))

    # ── Login ─────────────────────────────────────────────────────────────────
    @fastapi_app.get("/login")
    async def login_get(redirect_uri: str = "", state: str = ""):
        return HTMLResponse(_login_page(redirect_uri, state))

    @fastapi_app.post("/login")
    async def login_post(
        request: Request,
        email: str = Form(...),
        password: str = Form(...),
        redirect_uri: str = Form(...),
        state: str = Form(""),
    ):
        try:
            conn = get_conn()
            cur = ex(conn, "SELECT id, username, password, is_active FROM users WHERE email = ?", [email])
            rows = rows_to_dicts(cur)
        except Exception:
            return HTMLResponse(_login_page(redirect_uri, state, error="Database error, please try again."))

        if not rows:
            return HTMLResponse(_login_page(redirect_uri, state, error="Invalid email or password."))

        user = rows[0]
        if not user["is_active"]:
            return HTMLResponse(_login_page(redirect_uri, state,
                error="Your account is inactive. Please contact support."))
        if not verify_password(password, user["password"]):
            return HTMLResponse(_login_page(redirect_uri, state, error="Invalid email or password."))

        try:
            code = _create_oauth_code(conn, user["id"], redirect_uri)
        except Exception:
            return HTMLResponse(_login_page(redirect_uri, state,
                error="Failed to create session, please try again."))

        return _redirect_with_code(redirect_uri, code, state)

    # ── Sign-up ───────────────────────────────────────────────────────────────
    @fastapi_app.get("/signup")
    async def signup_get(redirect_uri: str = "", state: str = ""):
        return HTMLResponse(_signup_page(redirect_uri, state))

    @fastapi_app.post("/signup")
    async def signup_post(
        request: Request,
        username: str = Form(...),
        email: str = Form(...),
        password: str = Form(...),
        confirm: str = Form(...),
        redirect_uri: str = Form(...),
        state: str = Form(""),
    ):
        if len(username) < 3:
            return HTMLResponse(_signup_page(redirect_uri, state,
                error="Username must be at least 3 characters.",
                prefill_email=email, prefill_username=username))
        if len(password) < 8:
            return HTMLResponse(_signup_page(redirect_uri, state,
                error="Password must be at least 8 characters.",
                prefill_email=email, prefill_username=username))
        if password != confirm:
            return HTMLResponse(_signup_page(redirect_uri, state,
                error="Passwords do not match.",
                prefill_email=email, prefill_username=username))

        # Step 1: create user
        try:
            conn = get_conn()
            cur = ex(conn, "SELECT id FROM users WHERE email = ? OR username = ?", [email, username])
            if cur.fetchone():
                return HTMLResponse(_signup_page(redirect_uri, state,
                    error="That username or email is already registered. Try signing in instead.",
                    prefill_email=email, prefill_username=username))

            hashed_pw  = hash_password(password)
            api_key    = generate_api_key()
            created_at = now_utc().isoformat()
            cur = ex(conn,
                "INSERT INTO users(username, email, password, api_key, created_at) VALUES (?,?,?,?,?)",
                [username, email, hashed_pw, api_key, created_at]
            )
            conn.commit()
            user_id = cur.lastrowid  # only safe after commit
        except Exception:
            return HTMLResponse(_signup_page(redirect_uri, state,
                error="Registration failed, please try again.",
                prefill_email=email, prefill_username=username))

        # Step 2: auto-login — issue OAuth code immediately
        try:
            code = _create_oauth_code(conn, user_id, redirect_uri)
        except Exception:
            return HTMLResponse(_login_page(redirect_uri, state,
                success=f"Account created! Welcome, {username}. Please sign in."))

        return _redirect_with_code(redirect_uri, code, state)

    # ── Token exchange ────────────────────────────────────────────────────────
    @fastapi_app.post("/token")
    async def token(request: Request):
        content_type = request.headers.get("content-type", "")
        if "application/json" in content_type:
            body = await request.json()
            code = body.get("code", "")
        else:
            form = await request.form()
            code = form.get("code", "")

        if not code:
            return JSONResponse({"error": "missing code"}, status_code=400)

        try:
            conn = get_conn()
            cur = ex(conn,
                "SELECT user_id, expires_at, used FROM oauth_codes WHERE code = ?", [code])
            rows = rows_to_dicts(cur)
        except Exception:
            return JSONResponse({"error": "database error"}, status_code=500)

        if not rows:
            return JSONResponse({"error": "invalid code"}, status_code=400)

        row = rows[0]
        if row["used"]:
            return JSONResponse({"error": "code already used"}, status_code=400)
        if now_utc() > parse_utc(row["expires_at"]):
            return JSONResponse({"error": "code expired"}, status_code=400)

        ex(conn, "UPDATE oauth_codes SET used = 1 WHERE code = ?", [code])
        conn.commit()

        cur = ex(conn, "SELECT id, username FROM users WHERE id = ? AND is_active = 1", [row["user_id"]])
        user_rows = rows_to_dicts(cur)
        if not user_rows:
            return JSONResponse({"error": "user not found"}, status_code=400)

        user = user_rows[0]
        long_lived_token = generate_jwt(user["id"], user["username"], days=30)

        return JSONResponse({
            "access_token": long_lived_token,
            "token_type": "bearer",
            "expires_in": 30 * 24 * 3600,
        })


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))

    mcp_app = mcp.http_app()
    fastapi_app = FastAPI(title="ExpenseTracker MCP", lifespan=mcp_app.lifespan)
    _attach_oauth_routes(fastapi_app)
    fastapi_app.mount("/", mcp_app)

    uvicorn.run(fastapi_app, host="0.0.0.0", port=port)
