-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS app_auth_tokens(
  id                              INTEGER PRIMARY KEY,
  user_id                         TEXT NOT NULL UNIQUE,
  kind                            INTEGER NOT NULL,
  value                           TEXT NOT NULL,
  expires_at                      TEXT NOT NULL,
  created_at                      TEXT DEFAULT CURRENT_TIMESTAMP,

  FOREIGN KEY (user_id)
    REFERENCES app_auth_users(id)
      ON UPDATE NO ACTION
      ON DELETE CASCADE
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS app_auth_tokens;

-- +goose StatementEnd
