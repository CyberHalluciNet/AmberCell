CREATE DATABASE IF NOT EXISTS corp_app;
USE corp_app;

CREATE TABLE users (
  id INT PRIMARY KEY AUTO_INCREMENT,
  username VARCHAR(64),
  password_hash VARCHAR(128),
  role VARCHAR(32)
);

INSERT INTO users (username, password_hash, role) VALUES
  ('admin', 'sha256:fake', 'administrator'),
  ('finance', 'sha256:fake', 'finance'),
  ('canary', 'AMBERCELL_CANARY_PLACEHOLDER', 'canary');

CREATE TABLE transactions (
  id INT PRIMARY KEY AUTO_INCREMENT,
  amount DECIMAL(12,2),
  memo VARCHAR(255)
);

INSERT INTO transactions (amount, memo) VALUES (1200.00, 'Q4 staging');

CREATE TABLE config (
  k VARCHAR(64) PRIMARY KEY,
  v TEXT
);

INSERT INTO config (k, v) VALUES ('env', 'staging');

CREATE USER IF NOT EXISTS 'app'@'%' IDENTIFIED BY 'Welcome1';
GRANT SELECT, INSERT ON corp_app.* TO 'app'@'%';
FLUSH PRIVILEGES;
