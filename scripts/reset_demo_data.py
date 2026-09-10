"""Explicit local reset helper for demo data. Do not use against production evidence."""
from backend.constants import DB_PATH

if __name__ == "__main__":
    if DB_PATH.exists():
        DB_PATH.unlink()
        print(f"Removed local synthetic demo database: {DB_PATH}")
    else:
        print("No demo database exists.")
