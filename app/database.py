import os
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DB_PATH = os.environ.get("DATABASE_URL", "sqlite:///./safe_release.db")

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
