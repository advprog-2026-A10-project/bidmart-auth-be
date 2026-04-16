#[test]
fn auth_schema_migration_has_no_merge_conflict_markers() {
    let migration = include_str!("../migrations/20260223191047_auth_schema.sql");

    assert!(!migration.contains("<<<<<<<"));
    assert!(!migration.contains("======="));
    assert!(!migration.contains(">>>>>>>"));
}
