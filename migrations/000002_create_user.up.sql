create extension if not exists citext;

create type image as (
    provider text,
    url text
);

create table if not exists users (
    user_id text primary key default nanoid(8),
    name text not null,
    email citext not null constraint unique_user_email unique,
    avatar image,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);
