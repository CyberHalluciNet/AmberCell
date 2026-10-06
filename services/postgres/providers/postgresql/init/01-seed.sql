CREATE DATABASE corp_app;
\c corp_app

CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username TEXT,
  password_hash TEXT,
  role TEXT
);

INSERT INTO users (username, password_hash, role) VALUES
  ('admin', 'fakehash', 'administrator'),
  ('finance', 'fakehash', 'finance');

CREATE TABLE transactions (
  id SERIAL PRIMARY KEY,
  amount NUMERIC(12,2),
  memo TEXT
);

INSERT INTO transactions (amount, memo) VALUES (900.00, 'staging');

CREATE TABLE config (
  k TEXT PRIMARY KEY,
  v TEXT
);

INSERT INTO config (k, v) VALUES ('env', 'staging');

CREATE USER app WITH PASSWORD 'Welcome1';
GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA public TO app;
