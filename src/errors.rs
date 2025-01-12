use thiserror::Error;

#[derive(Error, Debug)]
pub enum PassmanError {
    #[error("Failed to read input")]
    ReadInputError,
    #[error("Passwords do not match")]
    PasswordMismatchError,
    #[error("Failed to initialize database")]
    InitDbError,
    #[error("Failed to store password in database")]
    StoreDbError,
    #[error("Failed to get from database")]
    GetDbError,
    #[error("Failed to update database")]
    UpdateDbError,
    #[error("Something went wrong with encryption")]
    CryptoError,
    #[error("Database not initialized. Run `passman init` first.")]
    DbNotInitializedError,
    #[error("Passman already initialized. Run `passman` to see options.")]
    DbAlreadyInitializedError,
    #[error("Password not found")]
    PasswordNotFoundError,
}
