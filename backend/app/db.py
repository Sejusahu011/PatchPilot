import aiosqlite
import os

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
        await db.commit()


async def get_db():
    return await aiosqlite.connect(DB_PATH)
