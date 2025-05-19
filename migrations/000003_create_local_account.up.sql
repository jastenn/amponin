create table if not exists local_accounts (
    local_account_id text primary key default nanoid(8),
    user_id text not null references users(user_id),
    password_hash bytea not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
)
