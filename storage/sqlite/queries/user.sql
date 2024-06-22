-- name: CreateUser :exec
INSERT INTO app_auth_users (id, email, phone_number, meta, password, is_verified)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(email) DO UPDATE SET
    phone_number = excluded.phone_number,
    meta = excluded.meta,
    password = excluded.password,
    is_verified = excluded.is_verified;

-- name: UpdateUserPassword :exec
UPDATE app_auth_users SET password = ? WHERE id = ?;

-- name: UpdateUserIsVerified :exec
UPDATE app_auth_users SET is_verified = ? AND is_verified_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: GetUserByID :one
SELECT id, email, phone_number, password, is_verified_at, is_verified, meta, created_at, updated_at
FROM app_auth_users WHERE id = ?;

-- name: GetUserByEmail :one
SELECT id, email, phone_number, password, is_verified_at, is_verified, meta, created_at, updated_at
FROM app_auth_users WHERE email = ?;

