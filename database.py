from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Local MySQL database (original setup)
SQLALCHEMY_DATABASE_URL = "mysql+mysqlconnector://marinell:marinellendaya@localhost/ai_health_db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    pool_pre_ping=True
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
