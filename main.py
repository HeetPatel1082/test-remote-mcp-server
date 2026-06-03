from datetime import date as date_cls
import json
from pathlib import Path
import sqlite3

from fastmcp import FastMCP

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "expenses.db"
CATEGORIES_PATH = BASE_DIR / "categories.json"

mcp = FastMCP("ExpenseTracker")


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA synchronous = NORMAL")
    return connection


def load_categories():
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


def expense_row_to_dict(row):
    return dict(row)


def init_db():
    with get_connection() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS expenses(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL,
                amount REAL NOT NULL,
                category TEXT NOT NULL,
                subcategory TEXT DEFAULT '',
                note TEXT DEFAULT ''
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_expenses_date ON expenses(date)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_expenses_category ON expenses(category)")

init_db()

@mcp.tool()
def add_expense(date, amount, category, subcategory="", note=""):
    '''Add a new expense entry to the database.'''
    date = validate_iso_date(date)
    amount = validate_amount(amount)
    validate_category(category, subcategory)

    with get_connection() as c:
        cur = c.execute(
            "INSERT INTO expenses(date, amount, category, subcategory, note) VALUES (?,?,?,?,?)",
            (date, amount, category, subcategory, note)
        )
        return {"status": "ok", "id": cur.lastrowid}

@mcp.tool()
def list_expenses(start_date, end_date):
    '''List expense entries within an inclusive date range.'''
    start_date = validate_iso_date(start_date)
    end_date = validate_iso_date(end_date)

    with get_connection() as c:
        cur = c.execute(
            """
            SELECT id, date, amount, category, subcategory, note
            FROM expenses
            WHERE date BETWEEN ? AND ?
            ORDER BY id ASC
            """,
            (start_date, end_date)
        )
        return [expense_row_to_dict(r) for r in cur.fetchall()]

@mcp.tool()
def summarize(start_date, end_date, category=None):
    '''Summarize expenses by category within an inclusive date range.'''
    start_date = validate_iso_date(start_date)
    end_date = validate_iso_date(end_date)
    if category:
        validate_category(category)

    with get_connection() as c:
        query = (
            """
            SELECT category, SUM(amount) AS total_amount
            FROM expenses
            WHERE date BETWEEN ? AND ?
            """
        )
        params = [start_date, end_date]

        if category:
            query += " AND category = ?"
            params.append(category)

        query += " GROUP BY category ORDER BY category ASC"

        cur = c.execute(query, params)
        return [expense_row_to_dict(r) for r in cur.fetchall()]


@mcp.tool()
def get_expense(expense_id):
    '''Get a single expense entry by its ID.'''
    with get_connection() as c:
        cur = c.execute(
            "SELECT id, date, amount, category, subcategory, note FROM expenses WHERE id = ?",
            (expense_id,)
        )
        row = cur.fetchone()
        if row is None:
            return {"found": False}
        return {"found": True, "expense": expense_row_to_dict(row)}


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
            with get_connection() as c:
                current = c.execute("SELECT category FROM expenses WHERE id = ?", (expense_id,)).fetchone()
            if current is None:
                return {"status": "not_found"}
            validate_category(current["category"], subcategory)
        updates.append("subcategory = ?")
        params.append(subcategory)

    if note is not None:
        updates.append("note = ?")
        params.append(note)

    if not updates:
        return {"status": "noop", "updated": 0}

    params.append(expense_id)
    with get_connection() as c:
        cur = c.execute(
            f"UPDATE expenses SET {', '.join(updates)} WHERE id = ?",
            params,
        )
        if cur.rowcount == 0:
            return {"status": "not_found", "updated": 0}
        return {"status": "ok", "updated": cur.rowcount}


@mcp.tool()
def delete_expense(expense_id):
    '''Delete an expense entry by its ID.'''
    with get_connection() as c:
        cur = c.execute("DELETE FROM expenses WHERE id = ?", (expense_id,))
        if cur.rowcount == 0:
            return {"status": "not_found", "deleted": 0}
        return {"status": "ok", "deleted": cur.rowcount}


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

    with get_connection() as c:
        cur = c.execute(
            """
            SELECT category, SUM(amount) AS total_amount, COUNT(*) AS expense_count
            FROM expenses
            WHERE date >= ? AND date < ?
            GROUP BY category
            ORDER BY total_amount DESC, category ASC
            """,
            (start_date, end_date),
        )
        return [expense_row_to_dict(r) for r in cur.fetchall()]

@mcp.resource("expense://categories", mime_type="application/json")
def categories():
    return json.dumps(load_categories(), indent=2)

if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=8000)