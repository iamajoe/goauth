-- name: CreateUser :exec
INSERT INTO app_auth_users (id, email, phone_number, meta, password, is_verified)
VALUES($1, $2, $3, $4, $5, $6)
ON CONFLICT (email)
DO UPDATE SET
    phone_number = EXCLUDED.phone_number,
    meta = EXCLUDED.meta,
    password = EXCLUDED.password,
    is_verified = EXCLUDED.is_verified;

