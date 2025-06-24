-- +goose Up
-- +goose StatementBegin
create extension if not exists "uuid-ossp";
create schema if not exists scudo;

create or replace function fn_update_updated_at_timestamp()
    returns trigger as $$
begin
    new.updated_at = current_timestamp;
    return new;
end;
$$ language plpgsql;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
drop function if exists fn_update_updated_at_timestamp;
drop schema if exists scudo;
drop extension if exists "uuid-ossp";
-- +goose StatementEnd
