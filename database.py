import os
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, ForeignKey, event
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
db_url_env = os.environ.get("DATABASE_URL")

if db_url_env:
    # Some providers like Heroku/Neon/Supabase provide postgres:// instead of postgresql://
    if db_url_env.startswith("postgres://"):
        db_url_env = db_url_env.replace("postgres://", "postgresql://", 1)
    SQLALCHEMY_DATABASE_URL = db_url_env
else:
    if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        SQLALCHEMY_DATABASE_URL = "sqlite:////tmp/threat_intelligence.db"
    else:
        db_file = os.path.join(BASE_DIR, "threat_intelligence.db")
        SQLALCHEMY_DATABASE_URL = f"sqlite:///{db_file}"

connect_args = {}
if SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args=connect_args)

# Enable WAL mode for SQLite to improve concurrent read/write throughput
if SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="analyst", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

class ScanHistory(Base):
    __tablename__ = "scan_history"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), index=True, nullable=True)
    url = Column(String, index=True, nullable=False)
    score = Column(Float, nullable=False)
    threat_level = Column(String, index=True, nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

class FeedbackReport(Base):
    __tablename__ = "feedback_report"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), index=True, nullable=True)
    url = Column(String, index=True, nullable=False)
    predicted_score = Column(Float, nullable=False)
    is_malicious = Column(Boolean, nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

class ContactMessage(Base):
    __tablename__ = "contact_messages"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), index=True, nullable=True)
    name = Column(String, nullable=False)
    email = Column(String, index=True, nullable=False)
    subject = Column(String, nullable=False)
    inquiry_type = Column(String, nullable=False)
    message = Column(String, nullable=False)
    status = Column(String, default="pending", nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    admin_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), index=True, nullable=True)
    action = Column(String, nullable=False)
    target = Column(String, nullable=True)
    details = Column(String, nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

def init_db():
    # Safely create tables without dropping existing data
    Base.metadata.create_all(bind=engine)
    
    # Auto-migration for SQLite to add new columns if upgrading existing database
    if SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
        try:
            with engine.connect() as conn:
                # Check user columns
                result = conn.execute(event.listen and engine.dialect.name == "sqlite" and __import__("sqlalchemy").text("PRAGMA table_info(users)"))
                columns = [row[1] for row in result.fetchall()]
                if "role" not in columns:
                    conn.execute(__import__("sqlalchemy").text("ALTER TABLE users ADD COLUMN role VARCHAR DEFAULT 'analyst' NOT NULL"))
                if "is_active" not in columns:
                    conn.execute(__import__("sqlalchemy").text("ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT 1 NOT NULL"))
                
                # Check contact_messages status column
                msg_res = conn.execute(__import__("sqlalchemy").text("PRAGMA table_info(contact_messages)"))
                msg_cols = [row[1] for row in msg_res.fetchall()]
                if "status" not in msg_cols:
                    conn.execute(__import__("sqlalchemy").text("ALTER TABLE contact_messages ADD COLUMN status VARCHAR DEFAULT 'pending' NOT NULL"))
                
                conn.commit()
        except Exception as e:
            print(f"Schema migration note: {e}")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


