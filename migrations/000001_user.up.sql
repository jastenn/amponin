CREATE TABLE IF NOT EXISTS users (
    username TEXT NOT NULL CONSTRAINT pkey_user PRIMARY KEY,
    email CITEXT NOT NULL CONSTRAINT unique_user_email UNIQUE,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS avatars (
    username TEXT NOT NULL REFERENCES users ON DELETE CASCADE,
    raw TEXT NOT NULL,
    thumbnail TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS accounts (
    account_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    username TEXT REFERENCES users ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT pkey_account PRIMARY KEY(account_id, provider)
);
