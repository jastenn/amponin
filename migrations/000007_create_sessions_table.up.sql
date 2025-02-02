create table if not exists sessions (
    token text primary key,
    data bytea not null,
    expiry timestamptz not null
);

create index sessions_expiry_idx on sessions (expiry);
