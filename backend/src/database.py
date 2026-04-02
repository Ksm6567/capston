from datetime import datetime
from pathlib import Path

from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent.parent
DB_PATH = PROJECT_ROOT / 'siem_db.sqlite'
FALLBACK_LOG = PROJECT_ROOT / 'logs' / 'siem_db_fallback.log'
DATABASE_URL = f"sqlite:///{DB_PATH.as_posix()}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
DB_ENABLED = True


class SiemLog(Base):
    __tablename__ = "siem_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    source = Column(String(50), nullable=False)
    message = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.now)


def _write_fallback(source: str, message: str):
    FALLBACK_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(FALLBACK_LOG, 'a', encoding='utf-8') as f:
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        f.write(f'[{now}] {source}: {message}\n')


def init_db():
    global DB_ENABLED
    try:
        Base.metadata.create_all(bind=engine)
    except Exception as e:
        DB_ENABLED = False
        print(f"[DB WARNING] SQLite disabled, falling back to file logging: {e}")


def save_log(source: str, message: str):
    if not DB_ENABLED:
        _write_fallback(source, message)
        return

    db = SessionLocal()
    try:
        log_entry = SiemLog(source=source, message=message)
        db.add(log_entry)
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"[DB WARNING] SQLite write failed, using fallback log: {e}")
        _write_fallback(source, message)
    finally:
        db.close()
