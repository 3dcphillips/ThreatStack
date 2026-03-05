import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# 1) Load environment variables from .env
#    By default, load_dotenv() looks for a .env file in the current working directory.
load_dotenv()

# 2) Read DATABASE_URL from environment
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL is not set. Add it to your .env file, e.g.:\n"
        "DATABASE_URL=postgresql+psycopg2://postgres:password@localhost:5432/threatintel"
    )

# 3) Create the SQLAlchemy engine
# pool_pre_ping helps avoid stale connections (useful in long-running services)
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
)

# 4) Create a configured "Session" class
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

# 5) Base class for ORM models
Base = declarative_base()


# 6) FastAPI dependency to get a DB session per request
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()