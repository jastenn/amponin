create table if not exists shelter_roles (
    shelter_id text not null references shelters(shelter_id),
    user_id text not null references users(user_id),
    role text not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);
