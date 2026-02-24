import os
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

_default_db = f"sqlite:///{Path(__file__).parent.parent / 'safe_release.db'}"
DB_PATH = os.environ.get("DATABASE_URL", _default_db)

engine = create_engine(
    DB_PATH,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def init_db():
    from app import models  # noqa: F401 — ensure models are registered
    Base.metadata.create_all(bind=engine)
