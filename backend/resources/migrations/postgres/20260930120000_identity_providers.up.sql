-- External OpenID Connect providers users can sign in with
CREATE TABLE identity_providers (
    id UUID NOT NULL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ,
    name TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    issuer TEXT NOT NULL,
    client_id TEXT NOT NULL,
    client_secret TEXT NOT NULL DEFAULT '',
    scopes TEXT NOT NULL DEFAULT 'openid profile email',
    auto_create_users BOOLEAN NOT NULL DEFAULT FALSE,
    auto_link_users BOOLEAN NOT NULL DEFAULT FALSE,
    auto_update_users BOOLEAN NOT NULL DEFAULT FALSE
);

-- Each row ties an account at an external provider (identified by its subject) to a local user
-- A user can be linked to a provider only once, and an external account can belong to one user only
CREATE TABLE identity_provider_links (
    id UUID NOT NULL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    identity_provider_id UUID NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    subject TEXT NOT NULL,
    email TEXT,
    UNIQUE (identity_provider_id, subject),
    UNIQUE (user_id, identity_provider_id)
);
