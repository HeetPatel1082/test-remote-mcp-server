from datetime import date as date_cls
import json
import os
from pathlib import Path
import libsql_client
from fastmcp import FastMCP

BASE_DIR = Path(__file__).resolve().parent
CATEGORIES_PATH = BASE_DIR / "categories.json"

# Grab Turso credentials, fallback to local file for desktop testing
DB_URL = os.environ.get("TURSO_DATABASE_URL", f"file:{BASE_DIR / 'expenses.db'}")
DB_TOKEN = os.environ.get("TURSO_AUTH_TOKEN", "")

mcp = FastMCP("ExpenseTracker")

def get_client():
    """Creates a connection to Turso (cloud) or local SQLite (desktop)."""
    return libsql_client.create_client_sync(url=DB_URL, auth_token=DB_TOKEN)

def load_categories():
    if not CATEGORIES_PATH.exists():
        return {
            "Food": ["Groceries", "Dining"],
            "Utilities": ["Electricity", "Internet"],
            "Other": []
        }
    with open(CATEGORIES_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

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

def init_db():
    try:
        with get_client() as client:
            client.execute("""
                CREATE TABLE IF NOT EXISTS expenses(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date TEXT NOT NULL,
                    amount REAL NOT NULL,
                    category TEXT NOT NULL,
                    subcategory TEXT DEFAULT '',
                    note TEXT DEFAULT ''
                )
            """)
            client.execute("CREATE INDEX IF NOT EXISTS idx_expenses_date ON expenses(date)")
            client.execute("CREATE INDEX IF NOT EXISTS idx_expenses_category ON expenses(category)")
    except Exception as e:
        print(f"Database initialization skipped or failed: {e}")

init_db()

@mcp.tool()
def add_expense(date, amount, category, subcategory="", note=""):
    '''Add a new expense entry to the database.'''
    date = validate_iso_date(date)
    amount = validate_amount(amount)
    validate_category(category, subcategory)

    with get_client() as client:
        rs = client.execute(
            "INSERT INTO expenses(date, amount, category, subcategory, note) VALUES (?,?,?,?,?)",
            [date, amount, category, subcategory, note]
        )
        return {"status": "ok", "id": rs.last_insert_rowid}

@mcp.tool()
def list_expenses(start_date, end_date):
    '''List expense entries within an inclusive date range.'''
    start_date = validate_iso_date(start_date)
    end_date = validate_iso_date(end_date)

    with get_client() as client:
        rs = client.execute(
            """
            SELECT id, date, amount, category, subcategory, note
            FROM expenses
            WHERE date BETWEEN ? AND ?
            ORDER BY id ASC
            """,
            [start_date, end_date]
        )
        cols = [col for col in rs.columns]
        return [dict(zip(cols, row)) for row in rs.rows]

@mcp.tool()
def summarize(start_date, end_date, category=None):
    '''Summarize expenses by category within an inclusive date range.'''
    start_date = validate_iso_date(start_date)
    end_date = validate_iso_date(end_date)
    if category:
        validate_category(category)

    with get_client() as client:
        query = "SELECT category, SUM(amount) AS total_amount FROM expenses WHERE date BETWEEN ? AND ?"
        params = [start_date, end_date]

        if category:
            query += " AND category = ?"
            params.append(category)

        query += " GROUP BY category ORDER BY category ASC"

        rs = client.execute(query, params)
        cols = [col for col in rs.columns]
        return [dict(zip(cols, row)) for row in rs.rows]

@mcp.tool()
def get_expense(expense_id):
    '''Get a single expense entry by its ID.'''
    with get_client() as client:
        rs = client.execute(
            "SELECT id, date, amount, category, subcategory, note FROM expenses WHERE id = ?",
            [expense_id]
        )
        if not rs.rows:
            return {"found": False}
        cols = [col for col in rs.columns]
        return {"found": True, "expense": dict(zip(cols, rs.rows[0]))}

@mcp.tool()
def update_expense(expense_id, date=None, amount=None, category=None, subcategory=None, note=None):
    '''Update fields on an existing expense entry.'''
    updates = []
    params = []

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
        if category is None:
            with get_client() as client:
                current = client.execute("SELECT category FROM expenses WHERE id = ?", [expense_id])
            if not current.rows:
                return {"status": "not_found"}
            current_cols = [col for col in current.columns]
            current_row = dict(zip(current_cols, current.rows[0]))
            validate_category(current_row["category"], subcategory)
        updates.append("subcategory = ?")
        params.append(subcategory)
    if note is not None:
        updates.append("note = ?")
        params.append(note)

    if not updates:
        return {"status": "noop", "updated": 0}

    params.append(expense_id)
    with get_client() as client:
        client.execute(f"UPDATE expenses SET {', '.join(updates)} WHERE id = ?", params)
        return {"status": "ok"}

@mcp.tool()
def delete_expense(expense_id):
    '''Delete an expense entry by its ID.'''
    with get_client() as client:
        client.execute("DELETE FROM expenses WHERE id = ?", [expense_id])
        return {"status": "ok"}

@mcp.tool()
def list_categories():
    '''Return the full category and subcategory catalog.'''
    return load_categories()

@mcp.tool()
def monthly_summary(year, month):
    '''Summarize expenses for a specific month.'''
    year = int(year)
    month = int(month)
    if month < 1 or month > 12:
        raise ValueError("month must be between 1 and 12")

    start_date = f"{year:04d}-{month:02d}-01"
    if month == 12:
        end_date = f"{year + 1:04d}-01-01"
    else:
        end_date = f"{year:04d}-{month + 1:02d}-01"

    with get_client() as client:
        rs = client.execute(
            """
            SELECT category, SUM(amount) AS total_amount, COUNT(*) AS expense_count
            FROM expenses
            WHERE date >= ? AND date < ?
            GROUP BY category
            ORDER BY total_amount DESC, category ASC
            """,
            [start_date, end_date]
        )
        cols = [col for col in rs.columns]
        return [dict(zip(cols, row)) for row in rs.rows]

@mcp.resource("expense://categories", mime_type="application/json")
def categories():
    return json.dumps(load_categories(), indent=2)

if __name__ == "__main__":
    mcp.run()