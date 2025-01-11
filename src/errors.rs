use thiserror::Error;

#[derive(Error, Debug)]
pub enum PassmanError {
    #[error("Error: Failed to read input")]
    ReadInputError,
    #[error("Error: Passwords do not match")]
    PasswordMismatchError,
    #[error("Error: Failed to initialize database")]
    InitDbError,
    #[error("Error: Failed to hash password")]
    HashPasswordError,
    #[error("Error: Failed to convert salt to string")]
    SaltStringError,
    #[error("Error: Failed to store password in database")]
    StoreDbError,
    #[error("Error: Failed to get from database")]
    GetDbError,
    #[error("Error: Failed to update database")]
    UpdateDbError,
}
