CREATE TABLE signatures (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  email_hash TEXT NOT NULL UNIQUE,
  iv TEXT NOT NULL,
  payload TEXT NOT NULL
);

CREATE TABLE submit_log (
  ip_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX submit_log_ip_time ON submit_log (ip_hash, created_at);
