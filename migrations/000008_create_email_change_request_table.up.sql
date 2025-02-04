create table if not exists email_change_request (
    code text not null default nanoid(12),
    user_id text not null references users(user_id),
    new_email citext not null,
    expires_at timestamptz not null,
    created_at timestamptz not null default now(),

    constraint unique_email_change_request_user unique(user_id)
);
