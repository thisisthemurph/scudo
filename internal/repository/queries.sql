-- name: UserWithEmailExists :one
select exists (select 1 from scudo.users where email = $1);

-- name: GetUserByID :one
select * from scudo.users where id = $1 limit 1;

-- name: GetUserByEmail :one
select * from scudo.users where email = $1 limit 1;

-- name: CreateUser :one
insert into scudo.users (email, hashed_password, metadata)
values ($1, $2, $3)
returning *;

-- name: GetRefreshTokensByUserID :many
select * from scudo.refresh_tokens where user_id = $1;

-- name: CreateRefreshToken :exec
insert into scudo.refresh_tokens (user_id, hashed_token, expires_at)
values ($1, $2, $3);

-- name: RevokeRefreshTokenByID :exec
update scudo.refresh_tokens
set revoked = true
where id = $1;