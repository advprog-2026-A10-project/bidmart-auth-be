#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UserAuthorization {
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
}
