-- +goose Up
-- +goose StatementBegin
create table if not exists scudo.users (
    id uuid primary key default gen_random_uuid(),
    email text not null unique,
    hashed_password text not null,
    metadata jsonb not null default '{}',
    created_at timestamp with time zone not null default now(),
    updated_at timestamp with time zone not null default now()
);

create index idx_users_email on scudo.users (email);

create trigger users_update_updated_at
    before update on scudo.users
    for each row
execute function fn_update_updated_at_timestamp();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
drop table if exists scudo.users;
-- +goose StatementEnd
