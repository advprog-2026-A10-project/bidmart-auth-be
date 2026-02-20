-- Add migration script here
-- Enable UUID generator
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

DO $$ BEGIN
  CREATE TYPE mfa_type AS ENUM ('TOTP','EMAIL');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE user_status AS ENUM ('ACTIVE','DISABLED','PENDING_VERIFICATION');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE token_type AS ENUM ('EMAIL_VERIFICATION','PASSWORD_RESET');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email varchar(255) UNIQUE NOT NULL,
  password_hash varchar NOT NULL,
  status user_status NOT NULL DEFAULT 'PENDING_VERIFICATION',
  mfa_enabled boolean NOT NULL DEFAULT false,
  mfa_type mfa_type,
  mfa_secret varchar,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS user_profiles (
  user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  first_name varchar,
  last_name varchar,
  address text,
  postal_code varchar,
  avatar_url varchar
);

CREATE TABLE IF NOT EXISTS sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash varchar UNIQUE NOT NULL,
  ip_address varchar,
  expired_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type token_type NOT NULL,
  token_hash varchar NOT NULL,
  expired_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (type, token_hash)
);

CREATE TABLE IF NOT EXISTS roles (
  id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name varchar UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS permissions (
  id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  slug varchar UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS role_permissions (
  role_id integer NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  permission_id integer NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
  PRIMARY KEY (role_id, permission_id)
);

-- OPTIONAL tapi biasanya dibutuhkan:
-- CREATE TABLE user_roles (
--   user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
--   role_id integer NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
--   PRIMARY KEY (user_id, role_id)
-- );

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens(user_id);