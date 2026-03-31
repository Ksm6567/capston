from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

# --- 연결 설정 ---
# SQLite 데이터베이스 파일 경로 (현재 폴더에 siem_db.sqlite 생성)
DATABASE_URL = "sqlite:///./siem_db.sqlite"

# SQLite의 경우 파일 기반이므로 멀티스레드 접근을 허용해야 합니다.
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- 로그 테이블 모델 ---
class SiemLog(Base):
    __tablename__ = "siem_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    source = Column(String(50), nullable=False)       # 'suricata' or 'yara'
    message = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.now)

def init_db():
    """DB와 테이블을 초기화합니다. 데이터베이스 파일이 없으면 자동 생성합니다."""
    Base.metadata.create_all(bind=engine)

def save_log(source: str, message: str):
    """로그를 DB에 저장합니다."""
    db = SessionLocal()
    try:
        log_entry = SiemLog(source=source, message=message)
        db.add(log_entry)
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"[DB ERROR] {e}")
    finally:
        db.close()
