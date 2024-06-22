-- name: CreateToken :exec
INSERT INTO app_auth_tokens (user_id, kind, value, expires_at)
VALUES (?, ?, ?, ?);

-- name: RemoveUserTokens :exec
DELETE FROM app_auth_tokens WHERE user_id = ?;

-- name: RemoveUserToken :exec
DELETE FROM app_auth_tokens WHERE user_id = ? AND value = ?;

-- name: IsTokenRegistered :one
SELECT EXISTS(SELECT 1 FROM app_auth_tokens WHERE value = ? LIMIT 1);
