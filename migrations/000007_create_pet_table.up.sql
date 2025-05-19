create type image as (
    provider text,
    url text
);
create type gender as enum('male', 'female');
create type pet_type as enum('cat', 'dog');
create table if not exists pets (
    pet_id text primary key default nanoid(8),
    name text not null,
    gender gender not null,
    type pet_type not null,
    images image[] not null,
    description text not null,
    registered_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
)
