use thiserror::Error;

#[derive(Error, Debug)]
pub enum PassmanError {
    #[error("Failed to read input")]
    ReadInputError,
    #[error("Passwords do not match")]
    PasswordMismatchError,
    #[error("Database error")]
    DbError,
}
