CREATE TABLE hosts (
  id SERIAL PRIMARY KEY,
  ip TEXT UNIQUE,
  hostname TEXT,
  os TEXT,
  cpu TEXT,
  ram TEXT,
  first_seen TIMESTAMP,
  last_seen TIMESTAMP,
  is_up BOOLEAN DEFAULT TRUE
);

CREATE TABLE services (
  id SERIAL PRIMARY KEY,
  proto VARCHAR(4) DEFAULT 'tcp',
  port INT,
  service TEXT,
  product TEXT,
  version TEXT,
  state VARCHAR(16),
  host_id INT REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE INDEX ix_services_host_port_proto ON services (host_id, port, proto);

CREATE TABLE websites (
  id SERIAL PRIMARY KEY,
  url TEXT,
  status BOOLEAN,
  title TEXT,
  host_id INT REFERENCES hosts(id) ON DELETE CASCADE,
  last_status BOOLEAN,
  last_title TEXT,
  last_notified_at TIMESTAMP
);

CREATE INDEX ix_websites_host ON websites (host_id);
