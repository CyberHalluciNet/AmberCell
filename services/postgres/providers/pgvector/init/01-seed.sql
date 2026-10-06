CREATE DATABASE corp_app;
\c corp_app

CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username TEXT,
  role TEXT
);

INSERT INTO users (username, role) VALUES
  ('admin', 'administrator'),
  ('finance', 'finance');

CREATE TABLE embeddings (
  id SERIAL PRIMARY KEY,
  label TEXT,
  embedding vector(3)
);

INSERT INTO embeddings (label, embedding) VALUES
  ('canary', '[0.1,0.2,0.3]');
