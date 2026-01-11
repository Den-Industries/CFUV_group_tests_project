# central_module/database.py
import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import redis

# Добавляем ?sslmode=disable для отключения SSL
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://survey_admin:survey_pass@localhost:5432/survey_db?sslmode=disable")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Redis клиент (если нужно)
redis_client = None
if os.getenv("REDIS_URL"):
    redis_client = redis.Redis.from_url(os.getenv("REDIS_URL"))

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
