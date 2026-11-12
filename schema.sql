-- Board to Notes database schema (Cloudflare D1)

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  pass_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS notes (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  title TEXT NOT NULL,
  subject TEXT NOT NULL,
  date TEXT NOT NULL,
  points TEXT NOT NULL,          -- JSON array of strings
  definitions TEXT NOT NULL,     -- JSON array of {term, def}
  raw_text TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notes_user ON notes(user_id, created_at);

-- Nested library folders (parent_id NULL = top level of the library).
-- notes.folder_id points at a folder (NULL = not in any folder). The API adds this
-- column to existing databases automatically (ALTER TABLE notes ADD COLUMN folder_id TEXT).
CREATE TABLE IF NOT EXISTS folders (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  parent_id TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_folders_user ON folders(user_id);

-- Original board photo, stored separately so the list query stays light
CREATE TABLE IF NOT EXISTS images (
  note_id TEXT PRIMARY KEY,
  data TEXT NOT NULL             -- data:image/jpeg;base64,...
);
