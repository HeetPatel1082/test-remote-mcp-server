from datetime import date as date_cls, datetime, timezone, timedelta
import json
import os
import secrets
import hashlib
from pathlib import Path

import bcrypt
import jwt
import libsql_experimental as libsql
from fastmcp import FastMCP

# ── Config ────────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
CATEGORIES_PATH = BASE_DIR / "categories.json"

DB_URL   = os.environ.get("TURSO_DATABASE_URL", f"file:{BASE_DIR / 'expenses.db'}")
DB_TOKEN = os.environ.get("TURSO_AUTH_TOKEN", "")
JWT_SECRET = os.environ.get("JWT_SECRET", "change-me-in-production-please")
JWT_EXPIRY_HOURS = int(os.environ.get("JWT_EXPIRY_HOURS", "72"))

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

def generate_jwt(user_id: int, username: str) -> str:
    payload = {
        "sub": user_id,
        "username": username,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRY_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def resolve_user(api_key: str = None, token: str = None) -> dict:
    """Resolve user from api_key or JWT token. Returns user dict or raises."""
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

        cur = ex(conn, "SELECT id, username, email FROM users WHERE id = ? AND is_active = 1", [payload["sub"]])
        rows = rows_to_dicts(cur)
        if not rows:
            raise ValueError("User not found or inactive")
        return rows[0]

# ── DB Init ───────────────────────────────────────────────────────────────────
def init_db():
    try:
        conn = get_conn()

        # Users table
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

        # Expenses table with user_id
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

        conn.commit()
        print("Database initialized successfully")
    except Exception as e:
        print(f"Database initialization skipped or failed: {e}")

init_db()

# ── Auth Tools ────────────────────────────────────────────────────────────────

@mcp.tool()
def register(username: str, email: str, password: str):
    """Register a new user. Returns api_key and jwt token."""
    if len(password) < 8:
        return {"status": "error", "message": "Password must be at least 8 characters"}

    conn = get_conn()

    # Check existing
    cur = ex(conn, "SELECT id FROM users WHERE email = ? OR username = ?", [email, username])
    if cur.fetchone():
        return {"status": "error", "message": "Username or email already exists"}

    hashed_pw  = hash_password(password)
    api_key    = generate_api_key()
    created_at = datetime.now(timezone.utc).isoformat()

    cur = ex(conn,
        "INSERT INTO users(username, email, password, api_key, created_at) VALUES (?,?,?,?,?)",
        [username, email, hashed_pw, api_key, created_at]
    )
    conn.commit()
    user_id = cur.lastrowid
    token = generate_jwt(user_id, username)

    return {
        "status": "ok",
        "message": f"Welcome, {username}!",
        "user_id": user_id,
        "api_key": api_key,
        "token": token,
        "token_expires_in": f"{JWT_EXPIRY_HOURS} hours",
    }

@mcp.tool()
def login(email: str, password: str):
    """Login with email and password. Returns fresh JWT token."""
    conn = get_conn()
    cur = ex(conn, "SELECT id, username, password, api_key, is_active FROM users WHERE email = ?", [email])
    rows = rows_to_dicts(cur)

    if not rows:
        return {"status": "error", "message": "Invalid email or password"}

    user = rows[0]

    if not user["is_active"]:
        return {"status": "error", "message": "Account is inactive"}

    if not verify_password(password, user["password"]):
        return {"status": "error", "message": "Invalid email or password"}

    token = generate_jwt(user["id"], user["username"])

    return {
        "status": "ok",
        "message": f"Welcome back, {user['username']}!",
        "user_id": user["id"],
        "api_key": user["api_key"],
        "token": token,
        "token_expires_in": f"{JWT_EXPIRY_HOURS} hours",
    }

@mcp.tool()
def get_profile(api_key: str = None, token: str = None):
    """Get current user profile."""
    user = resolve_user(api_key, token)
    return {"status": "ok", "user": user}

# ── Expense Tools ─────────────────────────────────────────────────────────────

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

    # Verify ownership
    conn = get_conn()
    cur = ex(conn, "SELECT id FROM expenses WHERE id = ? AND user_id = ?", [expense_id, user["id"]])
    if not cur.fetchone():
        return {"status": "not_found"}

    updates, params = [], []

    if date is not None:
        updates.append("date = ?")
        params.append(validate_iso_date(date))
    if amount is not None:
        updates.append("amount = ?")
        params.append(validate_amount(amount))
    if category is not None:
        validate_category(category, subcategory or "")
        updates.append("category = ?")
        params.append(category)
    if subcategory is not None:
        updates.append("subcategory = ?")
        params.append(subcategory)
    if note is not None:
        updates.append("note = ?")
        params.append(note)

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

    conn  = get_conn()
    query  = "SELECT category, SUM(amount) AS total_amount FROM expenses WHERE user_id = ? AND date BETWEEN ? AND ?"
    params = [user["id"], start_date, end_date]

    if category:
        query += " AND category = ?"
        params.append(category)

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

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8080))
    mcp.run(transport="http", host="0.0.0.0", port=port)