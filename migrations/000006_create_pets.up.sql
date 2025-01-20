DO $$ BEGIN
    create type pet_type as enum ('dog', 'cat');
    create type gender as enum ('male', 'female');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

create table if not exists pets (
    pet_id text primary key default nanoid(8),
    shelter_id text not null references shelters(shelter_id),
    name text not null,
    pet_type pet_type not null, 
    gender gender not null,
    birth_date date not null,
    image_urls text[] not null,
    is_birth_date_approx bool not null,
    description text not null,
    registered_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);
