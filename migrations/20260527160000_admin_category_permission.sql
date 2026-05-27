INSERT INTO permissions (slug)
VALUES ('category:manage')
ON CONFLICT (slug) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.slug = 'category:manage'
WHERE UPPER(r.name) = 'ADMIN'
ON CONFLICT (role_id, permission_id) DO NOTHING;
