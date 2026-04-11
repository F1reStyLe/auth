-- +goose Up
ALTER TABLE users
    ADD COLUMN account_status TEXT NOT NULL DEFAULT 'active';

CREATE TABLE roles (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);

INSERT INTO roles (name)
VALUES
    ('user'),
    ('moderator'),
    ('admin');

ALTER TABLE users
    ADD COLUMN role_id BIGINT REFERENCES roles(id) ON DELETE RESTRICT;

UPDATE users
SET role_id = r.id
FROM roles r
WHERE r.name = 'user';

ALTER TABLE users
ALTER COLUMN role_id SET NOT NULL;

CREATE TABLE user_profiles (
    user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    full_name TEXT NOT NULL DEFAULT '',
    avatar_url TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT '',
    timezone TEXT NOT NULL DEFAULT 'UTC',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO user_profiles (user_id)
SELECT id FROM users
ON CONFLICT (user_id) DO NOTHING;

CREATE TABLE oauth_accounts (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (provider, provider_user_id)
);

CREATE INDEX idx_oauth_accounts_user_id ON oauth_accounts(user_id);

CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    actor_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);

-- +goose Down
DROP TABLE audit_logs;
DROP TABLE oauth_accounts;
DROP TABLE user_profiles;
ALTER TABLE users
DROP COLUMN role_id;
DROP TABLE roles;
ALTER TABLE users
DROP COLUMN account_status;
