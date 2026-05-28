CREATE TABLE IF NOT EXISTS admin_security_policy (
    id INTEGER PRIMARY KEY,
    max_concurrent_sessions INTEGER NOT NULL DEFAULT 3,
    enforcement_mode VARCHAR(20) NOT NULL DEFAULT 'REVOKE_OLDEST',
    force_mfa_for_admin BOOLEAN NOT NULL DEFAULT true,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_admin_security_policy_mode CHECK (
        enforcement_mode IN ('REJECT_NEW', 'REVOKE_OLDEST')
    ),
    CONSTRAINT chk_admin_security_policy_max CHECK (
        max_concurrent_sessions >= 1
    )
);

INSERT INTO admin_security_policy (
    id,
    max_concurrent_sessions,
    enforcement_mode,
    force_mfa_for_admin
)
VALUES (1, 3, 'REVOKE_OLDEST', TRUE)
ON CONFLICT (id) DO NOTHING;
