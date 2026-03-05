from sqlalchemy import text
from app.database import engine

with engine.connect() as conn:
    result = conn.execute(text("SELECT 1;"))
    print("DB OK ->", result.scalar())