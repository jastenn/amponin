create table if not exists local_accounts (
    user_id text not null references users(user_id) on delete cascade,
    password_hash bytea not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
)
