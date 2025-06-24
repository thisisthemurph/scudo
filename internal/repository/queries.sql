-- name: UserWithEmailExists :one
select exists (select 1 from scudo.users where email = $1);

-- name: GetUserByEmail :one
select * from scudo.users where email = $1 limit 1;

-- name: CreateUser :one
insert into scudo.users (email, hashed_password)
values ($1, $2)
returning *;

-- name: CreateRefreshToken :exec
insert into scudo.refresh_tokens (user_id, hashed_token, expires_at)
values ($1, $2, $3);
