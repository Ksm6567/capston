import hashlib
import hmac
import os
import secrets
import sys
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote_plus

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text, create_engine, text
from sqlalchemy.engine import URL
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR.parent) not in sys.path:
    sys.path.append(str(BASE_DIR.parent))

try:
    from backend.runtime_paths import app_root
except ModuleNotFoundError:
    from runtime_paths import app_root

PROJECT_ROOT = app_root()
FALLBACK_LOG = PROJECT_ROOT / "logs" / "db_fallback.log"
DB_ENABLED = True

DB_HOST = os.environ.get("SIEM_DB_HOST", "127.0.0.1")
DB_PORT = int(os.environ.get("SIEM_DB_PORT", "3306"))
DB_NAME = os.environ.get("SIEM_DB_NAME", "siem_server")
DB_USER = os.environ.get("SIEM_DB_USER", "root")
DB_PASSWORD = os.environ.get("SIEM_DB_PASSWORD", "1111")
DEFAULT_ADMIN_USERNAME = os.environ.get("SIEM_DEFAULT_USERNAME", "admin")
DEFAULT_ADMIN_PASSWORD = os.environ.get("SIEM_DEFAULT_PASSWORD", "admin1234")
SESSION_DURATION_HOURS = int(os.environ.get("SIEM_SESSION_HOURS", "12"))

Base = declarative_base()
engine = None
SessionLocal = None


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    password_hash = Column(String(128), nullable=False)
    password_salt = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=datetime.now, nullable=False)

    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")
    logs = relationship("SiemLog", back_populates="user")


class UserSession(Base):
    __tablename__ = "user_sessions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    token = Column(String(128), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    expires_at = Column(DateTime, nullable=False)

    user = relationship("User", back_populates="sessions")


class SiemLog(Base):
    __tablename__ = "siem_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    source = Column(String(50), nullable=False)
    message = Column(Text, nullable=False)
    username = Column(String(50), ForeignKey("users.username"), nullable=True, index=True)
    timestamp = Column(DateTime, default=datetime.now, nullable=False)

    user = relationship("User", back_populates="logs")


def _server_url() -> URL:
    return URL.create(
        "mysql+pymysql",
        username=DB_USER,
        password=DB_PASSWORD or None,
        host=DB_HOST,
        port=DB_PORT,
    )


def _database_url() -> str:
    password = quote_plus(DB_PASSWORD) if DB_PASSWORD else ""
    auth_part = DB_USER
    if password:
        auth_part = f"{DB_USER}:{password}"
    return f"mysql+pymysql://{auth_part}@{DB_HOST}:{DB_PORT}/{DB_NAME}?charset=utf8mb4"


def _write_fallback(source: str, message: str, username: str | None = None):
    FALLBACK_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(FALLBACK_LOG, "a", encoding="utf-8") as handle:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        owner = username or "system"
        handle.write(f"[{now}] [{owner}] {source}: {message}\n")


def _hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        100_000,
    ).hex()


def hash_password(password: str) -> tuple[str, str]:
    salt = secrets.token_hex(16)
    return salt, _hash_password(password, salt)


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    return hmac.compare_digest(_hash_password(password, salt), expected_hash)


def _ensure_database_exists():
    bootstrap_engine = create_engine(_server_url(), pool_pre_ping=True)
    with bootstrap_engine.connect() as connection:
        connection.execute(text(f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"))
        connection.commit()
    bootstrap_engine.dispose()


def _seed_default_admin():
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.username == DEFAULT_ADMIN_USERNAME).first()
        if existing:
            return

        salt, password_hash = hash_password(DEFAULT_ADMIN_PASSWORD)
        db.add(
            User(
                username=DEFAULT_ADMIN_USERNAME,
                password_hash=password_hash,
                password_salt=salt,
            )
        )
        db.commit()
    finally:
        db.close()


def init_db():
    global DB_ENABLED, engine, SessionLocal
    try:
        _ensure_database_exists()
        engine = create_engine(_database_url(), pool_pre_ping=True)
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        Base.metadata.create_all(bind=engine)
        _seed_default_admin()
    except Exception as exc:
        DB_ENABLED = False
        engine = None
        SessionLocal = None
        print(f"[DB WARNING] MySQL disabled, falling back to file logging: {exc}")


def is_db_enabled() -> bool:
    return DB_ENABLED and SessionLocal is not None


def is_admin_username(username: str | None) -> bool:
    return (username or "").strip() == DEFAULT_ADMIN_USERNAME


def create_user(username: str, password: str) -> tuple[bool, str]:
    if not DB_ENABLED or SessionLocal is None:
        return False, "Database is unavailable."

    normalized_username = (username or "").strip()
    if not normalized_username or not password:
        return False, "Username and password are required."

    db = SessionLocal()
    try:
        if db.query(User).filter(User.username == normalized_username).first():
            return False, "That username is already in use."

        salt, password_hash = hash_password(password)
        db.add(User(username=normalized_username, password_hash=password_hash, password_salt=salt))
        db.commit()
        return True, "User created."
    except Exception as exc:
        db.rollback()
        return False, f"Failed to create the user: {exc}"
    finally:
        db.close()


def authenticate_user(username: str, password: str) -> User | None:
    if not DB_ENABLED or SessionLocal is None:
        return None

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == (username or "").strip()).first()
        if not user:
            return None
        if not verify_password(password or "", user.password_salt, user.password_hash):
            return None
        return user
    finally:
        db.close()


def create_session(username: str) -> tuple[str | None, datetime | None]:
    if not DB_ENABLED or SessionLocal is None:
        return None, None

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            return None, None

        token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(hours=SESSION_DURATION_HOURS)
        db.add(UserSession(user_id=user.id, token=token, expires_at=expires_at))
        db.commit()
        return token, expires_at
    except Exception:
        db.rollback()
        return None, None
    finally:
        db.close()


def get_session(token: str) -> dict | None:
    if not DB_ENABLED or SessionLocal is None or not token:
        return None

    db = SessionLocal()
    try:
        session = (
            db.query(UserSession)
            .join(User)
            .filter(UserSession.token == token)
            .first()
        )
        if not session or session.expires_at < datetime.now():
            if session:
                db.delete(session)
                db.commit()
            return None

        return {
            "username": session.user.username,
            "is_admin": is_admin_username(session.user.username),
            "expires_at": session.expires_at,
        }
    finally:
        db.close()


def delete_session(token: str):
    if not DB_ENABLED or SessionLocal is None or not token:
        return

    db = SessionLocal()
    try:
        session = db.query(UserSession).filter(UserSession.token == token).first()
        if session:
            db.delete(session)
            db.commit()
    finally:
        db.close()


def save_log(source: str, message: str, username: str | None = None):
    if not DB_ENABLED or SessionLocal is None:
        _write_fallback(source, message, username)
        return

    db = SessionLocal()
    try:
        db.add(SiemLog(source=source, message=message, username=username))
        db.commit()
    except Exception as exc:
        db.rollback()
        print(f"[DB WARNING] MySQL write failed, using fallback log: {exc}")
        _write_fallback(source, message, username)
    finally:
        db.close()


def get_log_dates_for_user(valid_sources: set[str], username: str) -> dict[str, list[str]]:
    result = {source: [] for source in sorted(valid_sources)}
    if not DB_ENABLED or SessionLocal is None:
        return result

    db = SessionLocal()
    try:
        rows = (
            db.query(SiemLog.source, SiemLog.timestamp)
            .filter(SiemLog.username == username)
            .all()
        )
        for source, timestamp in rows:
            if source not in result or not timestamp:
                continue
            date_str = timestamp.strftime("%Y-%m-%d")
            if date_str not in result[source]:
                result[source].append(date_str)
    finally:
        db.close()

    for source in result:
        result[source].sort(reverse=True)
    return result


def get_db_log_content(source: str, date: str, username: str) -> str:
    if not DB_ENABLED or SessionLocal is None:
        return ""

    db = SessionLocal()
    try:
        rows = (
            db.query(SiemLog)
            .filter(SiemLog.source == source)
            .filter(SiemLog.username == username)
            .order_by(SiemLog.timestamp.asc())
            .all()
        )
    finally:
        db.close()

    matching_lines = []
    for row in rows:
        if not row.timestamp or row.timestamp.strftime("%Y-%m-%d") != date:
            continue
        matching_lines.append(f"[{row.timestamp.strftime('%H:%M:%S')}] {row.message}")

    return "\n".join(matching_lines)


def delete_logs_for_user(username: str) -> int:
    if not DB_ENABLED or SessionLocal is None or not username:
        return 0

    db = SessionLocal()
    try:
        deleted_count = (
            db.query(SiemLog)
            .filter(SiemLog.username == username)
            .delete(synchronize_session=False)
        )
        db.commit()
        return deleted_count
    except Exception:
        db.rollback()
        return 0
    finally:
        db.close()


def delete_logs_for_user_on_date(username: str, source: str, date: str) -> int:
    if not DB_ENABLED or SessionLocal is None or not username or not source or not date:
        return 0

    db = SessionLocal()
    try:
        rows = (
            db.query(SiemLog.id, SiemLog.timestamp)
            .filter(SiemLog.username == username)
            .filter(SiemLog.source == source)
            .all()
        )
        ids_to_delete = [
            row_id
            for row_id, timestamp in rows
            if timestamp and timestamp.strftime("%Y-%m-%d") == date
        ]
        if not ids_to_delete:
            return 0

        deleted_count = (
            db.query(SiemLog)
            .filter(SiemLog.id.in_(ids_to_delete))
            .delete(synchronize_session=False)
        )
        db.commit()
        return deleted_count
    except Exception:
        db.rollback()
        return 0
    finally:
        db.close()


def list_usernames() -> list[str]:
    if not DB_ENABLED or SessionLocal is None:
        return []

    db = SessionLocal()
    try:
        rows = db.query(User.username).order_by(User.username.asc()).all()
        return [username for (username,) in rows if username]
    finally:
        db.close()
