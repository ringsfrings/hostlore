from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String, create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker

from app.config_loader import load_config

Base = declarative_base()
engine = None
SessionLocal = None

def init_db(force: bool = False):
    """Create tables if missing, then run lightweight migrations for existing installs.

    Idempotent: subsequent calls are no-ops unless force=True (used when config changes)."""
    global engine, SessionLocal
    if engine is not None and not force:
        return
    config = load_config()
    db_uri = config.get("database", {}).get("uri")
    if not db_uri:
        raise ValueError("Database URI not found in config")
    engine = create_engine(db_uri, pool_pre_ping=True)
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
    # Change tracking: when the host was first/last seen up, and whether the
    # latest complete scan of its range found it up.
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    is_up = Column(Boolean, default=True)
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
      - Add first_seen/last_seen/is_up to hosts
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
        conn.execute(text("ALTER TABLE hosts ADD COLUMN IF NOT EXISTS first_seen TIMESTAMP;"))
        conn.execute(text("ALTER TABLE hosts ADD COLUMN IF NOT EXISTS last_seen TIMESTAMP;"))
        conn.execute(text("ALTER TABLE hosts ADD COLUMN IF NOT EXISTS is_up BOOLEAN DEFAULT TRUE;"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_hosts_ip ON hosts (ip);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_services_host ON services (host_id);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_services_port ON services (port);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_services_host_port_proto ON services (host_id, port, proto);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_websites_host ON websites (host_id);"))
