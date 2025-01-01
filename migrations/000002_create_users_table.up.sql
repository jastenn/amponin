create extension if not exists citext;
create table if not exists users (
    user_id text primary key default nanoid(8),
    display_name text not null,
    email citext not null constraint unique_user_email UNIQUE,
    avatar_url text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);
