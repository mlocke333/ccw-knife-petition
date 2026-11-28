DROP TABLE signatures;

CREATE TABLE signatures (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  city TEXT NOT NULL,
  county TEXT NOT NULL,
  zip TEXT NOT NULL,
  ccw_holder TEXT NOT NULL,
  comment TEXT NOT NULL
);
