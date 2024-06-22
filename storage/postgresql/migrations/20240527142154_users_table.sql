-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS app_auth_users(
  id                              UUID PRIMARY KEY,
  email                           TEXT NOT NULL UNIQUE,
  phone_number                    TEXT DEFAULT '',

  password                        TEXT NOT NULL,
  is_verified_at                  TIMESTAMP WITH TIME ZONE,
  is_verified                     BOOLEAN DEFAULT FALSE,
  meta                            JSONB NOT NULL,

  -- TODO: SSO?!
  -- TODO: 2FA?!
  
  created_at                      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at                      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
TRUNCATE app_auth_users CASCADE;
DROP TABLE IF EXISTS app_auth_users;

-- +goose StatementEnd

