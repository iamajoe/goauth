-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS app_auth_users(
  id                              TEXT PRIMARY KEY,
  email                           TEXT NOT NULL UNIQUE,
  phone_number                    TEXT DEFAULT '',

  password                        TEXT NOT NULL,
  is_verified_at                  TEXT,
  is_verified                     BOOLEAN DEFAULT FALSE,
  meta                            JSON DEFAULT '{}',

  -- TODO: SSO?!
  -- TODO: 2FA?!
  
  created_at                      TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at                      TEXT DEFAULT CURRENT_TIMESTAMP
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS app_auth_users;

-- +goose StatementEnd

