from sqlalchemy import (
    create_engine, Column, Integer, String, Boolean, ForeignKey, Index, DateTime, text
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from app.config_loader import load_config

Base = declarative_base()
engine = None
SessionLocal = None

def init_db():
    """Create tables if missing, then run lightweight migrations for existing installs."""
    global engine, SessionLocal
    config = load_config()
    db_uri = config.get("database", {}).get("uri")
    if not db_uri:
        raise ValueError("Database URI not found in config")
    engine = create_engine(db_uri)
    SessionLocal = sessionmaker(bind=engine)
    Base.metadata.create_all(bind=engine)
    _run_migrations(engine)

def get_session():
    if SessionLocal is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    return SessionLocal()

class Host(Base):
    __tablename__ = 'hosts'
    id = Column(Integer, primary_key=True)
    ip = Column(String, unique=True, index=True)
    hostname = Column(String)
    os = Column(String)
    cpu = Column(String)
    ram = Column(String)
    services = relationship("Service", back_populates="host", cascade="all, delete-orphan")
    website = relationship("Website", uselist=False, back_populates="host", cascade="all, delete-orphan")

class Service(Base):
    __tablename__ = 'services'
    id = Column(Integer, primary_key=True)
    proto = Column(String(4), default="tcp")
    port = Column(Integer, index=True)
    service = Column(String)
    product = Column(String)
    version = Column(String)
    state = Column(String(16))
    host_id = Column(Integer, ForeignKey('hosts.id'), index=True)
    host = relationship("Host", back_populates="services")

Index("ix_services_host_port_proto", Service.host_id, Service.port, Service.proto)

class Website(Base):
    __tablename__ = 'websites'
    id = Column(Integer, primary_key=True)
    url = Column(String)
    status = Column(Boolean)
    title = Column(String)
    host_id = Column(Integer, ForeignKey('hosts.id'), unique=True, index=True)
    host = relationship("Host", back_populates="website")

    # Alert-on-change metadata (already requested in Sprint 2)
    last_status = Column(Boolean)
    last_title = Column(String)
    last_notified_at = Column(DateTime)

Index("ix_websites_host", Website.host_id)

def _run_migrations(engine):
    """
    Minimal, idempotent migrations (Postgres):
      - Add proto/state to services
      - Add last_* to websites
      - Ensure helpful indexes
    """
    with engine.begin() as conn:
        conn.execute(text("""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name='services' AND column_name='proto'
                ) THEN
                    ALTER TABLE services ADD COLUMN proto VARCHAR(4) DEFAULT 'tcp';
                END IF;
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name='services' AND column_name='state'
                ) THEN
                    ALTER TABLE services ADD COLUMN state VARCHAR(16);
                END IF;
            END$$;
        """))
        conn.execute(text("""
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                    WHERE table_name='websites' AND column_name='last_status') THEN
                    ALTER TABLE websites ADD COLUMN last_status BOOLEAN;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                    WHERE table_name='websites' AND column_name='last_title') THEN
                    ALTER TABLE websites ADD COLUMN last_title TEXT;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                    WHERE table_name='websites' AND column_name='last_notified_at') THEN
                    ALTER TABLE websites ADD COLUMN last_notified_at TIMESTAMP;
                END IF;
            END$$;
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_hosts_ip ON hosts (ip);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_services_host ON services (host_id);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_services_port ON services (port);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_services_host_port_proto ON services (host_id, port, proto);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_websites_host ON websites (host_id);"))
