-- users table (single definition with all columns)
CREATE TABLE IF NOT EXISTS users (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  username   TEXT    UNIQUE NOT NULL,
  email      TEXT    UNIQUE NOT NULL,
  password   TEXT    NOT NULL,
  is_admin   INTEGER NOT NULL DEFAULT 0,
  google_id  TEXT    UNIQUE,
  role       TEXT    NOT NULL DEFAULT 'user',
  agent_category TEXT
);

-- tickets table
CREATE TABLE IF NOT EXISTS tickets (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  title       TEXT    NOT NULL,
  description TEXT    NOT NULL,
  user_id     INTEGER NOT NULL,
  assigned_agent_id INTEGER,
  status      TEXT    NOT NULL DEFAULT 'Open',
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  
  -- Common user information
  first_name  TEXT,
  last_name   TEXT,
  email       TEXT,
  phone       TEXT,
  room        TEXT,

  -- General ticket fields
  user_type   TEXT,
  group_id    TEXT,
  category_id TEXT,
  requester_email TEXT,
  building    TEXT,

  -- Service-specific fields
  service_type TEXT,
  service_category TEXT,
  
  -- Academic fields
  document_type TEXT,
  delivery_method TEXT,
  
  -- IT fields
  device_type TEXT,
  operating_system TEXT,
  
  -- Facility fields
  location TEXT,
  preferred_date TEXT,
  
  -- Administrative fields
  id_type TEXT,
  urgency TEXT,
  
  FOREIGN KEY(user_id) REFERENCES users(id)
);

-- comments table
CREATE TABLE IF NOT EXISTS comments (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ticket_id   INTEGER NOT NULL,
  user_id     INTEGER NOT NULL,
  content     TEXT NOT NULL,
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(ticket_id) REFERENCES tickets(id),
  FOREIGN KEY(user_id) REFERENCES users(id)
);

-- articles table
CREATE TABLE IF NOT EXISTS articles (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  title       TEXT NOT NULL,
  slug        TEXT UNIQUE NOT NULL,
  content     TEXT NOT NULL,
  category    TEXT NOT NULL,
  icon        TEXT,
  published   INTEGER NOT NULL DEFAULT 0,
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- services table
CREATE TABLE IF NOT EXISTS services (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  slug        TEXT    UNIQUE NOT NULL,
  title       TEXT    NOT NULL,
  description TEXT,
  icon        TEXT,
  color       TEXT    NOT NULL
);