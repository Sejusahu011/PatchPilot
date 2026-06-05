import aiosqlite
import os
import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "patchpilot.db")


async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id          TEXT PRIMARY KEY,
                job_id      TEXT NOT NULL,
                rule_id     TEXT,
                severity    TEXT,
                category    TEXT,
                file_path   TEXT,
                line_number INTEGER,
                cwe         TEXT,
                scanner     TEXT,
                message     TEXT,
                created_at  TEXT DEFAULT (datetime('now'))
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS jobs (
                job_id       TEXT PRIMARY KEY,
                project_name TEXT,
                scan_method  TEXT,
                created_at   TEXT DEFAULT (datetime('now'))
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS verify_outcomes (
                id TEXT PRIMARY KEY,
                job_id TEXT NOT NULL,
                passed INTEGER NOT NULL,
                new_issues_introduced INTEGER DEFAULT 0,
                verified_at TEXT DEFAULT (datetime('now'))
            )
        """)
        await db.commit()


async def get_db():
    return await aiosqlite.connect(DB_PATH)

async def get_trend_data(limit: int = 6):
    """Fetches the finding counts for the last N scans for the dashboard."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("""
            SELECT 
                j.created_at, 
                COUNT(f.id) as findings_count
            FROM jobs j
            LEFT JOIN findings f ON j.job_id = f.job_id
            GROUP BY j.job_id
            ORDER BY j.created_at DESC
            LIMIT ?
        """, (limit,))
        
        rows = await cursor.fetchall()
        rows = list(reversed(rows))
        
        formatted_data = []
        for row in rows:
            dt_obj = datetime.datetime.strptime(row["created_at"], "%Y-%m-%d %H:%M:%S")
            formatted_data.append({
                "date": dt_obj.strftime("%b %d"),
                "findings": row["findings_count"]
            })
            
        return formatted_data