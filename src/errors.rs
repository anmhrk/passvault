use thiserror::Error;

#[derive(Error, Debug)]
pub enum PassmanError {
    #[error("Failed to read input")]
    ReadInputError,
    #[error("Passwords do not match")]
    PasswordMismatchError,
    #[error("Failed to initialize database")]
    InitDbError,
    #[error("Failed to hash password")]
    HashPasswordError,
    #[error("Failed to store password in database")]
    StoreDbError,
    #[error("Database get error")]
    GetDbError,
}
