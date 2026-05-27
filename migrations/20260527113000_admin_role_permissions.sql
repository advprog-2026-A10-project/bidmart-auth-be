INSERT INTO permissions (slug)
VALUES
    ('admin:access'),
    ('admin:auth:read'),
    ('user:suspend'),
    ('listing:moderate'),
    ('order:intervene'),
    ('wallet:adjust')
ON CONFLICT (slug) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.slug IN (
    'admin:access',
    'admin:auth:read',
    'user:suspend',
    'listing:moderate',
    'order:intervene',
    'wallet:adjust'
)
WHERE UPPER(r.name) = 'ADMIN'
ON CONFLICT (role_id, permission_id) DO NOTHING;
