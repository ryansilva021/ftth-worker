-- migrations/0001_init.sql
CREATE TABLE IF NOT EXISTS ctos (
  CTO_ID TEXT PRIMARY KEY,
  NOME TEXT,
  RUA TEXT,
  BAIRRO TEXT,
  LAT REAL NOT NULL,
  LNG REAL NOT NULL,
  CAPACIDADE INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_ctos_lat_lng ON ctos(LAT, LNG);
