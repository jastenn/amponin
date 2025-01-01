create table if not exists local_accounts (
    user_id text primary key references users(user_id),
    password_hash bytea not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);
    
    
