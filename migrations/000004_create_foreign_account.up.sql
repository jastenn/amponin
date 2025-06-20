create table if not exists foreign_accounts(
    user_id text not null references users(user_id) on delete cascade,
    provider text not null, -- provider name, e.g. google or facebook
    provider_id text not null, -- assigned id of the account by the provider
    created_at timestamptz not null default now(),
    
    constraint unique_foreign_account unique(provider_id, provider)
)
