create table if not exists shelters (
    shelter_id text primary key default nanoid(8),
    name text not null,
    avatar_url text, 
    address text not null,
    coordinates geometry not null,
    description text not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
)
