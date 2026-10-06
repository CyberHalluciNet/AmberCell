CREATE DATABASE corp_app;
\c corp_app

CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username TEXT,
  role TEXT
);

INSERT INTO users (username, role) VALUES
  ('admin', 'administrator'),
  ('finance', 'finance');

CREATE TABLE metrics (
  time TIMESTAMPTZ NOT NULL,
  device TEXT,
  value DOUBLE PRECISION
);

SELECT create_hypertable('metrics', 'time', if_not_exists => TRUE);

INSERT INTO metrics (time, device, value) VALUES
  (NOW(), 'sensor-canary', 1.0);
