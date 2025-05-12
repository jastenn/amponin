CREATE TYPE role as ENUM('super_admin', 'admin', 'editor');

CREATE TABLE IF NOT EXISTS shelter_roles (
    shelter_id text not null references shelters(shelter_id),
    user_id text not null references users(user_id),
    role role not null,

    primary key (shelter_id, user_id) 
);
