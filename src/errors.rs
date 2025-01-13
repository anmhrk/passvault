use thiserror::Error;

#[derive(Error, Debug)]
pub enum PassvaultError {
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
    #[error("Failed to delete password from database")]
    DeleteDbError,
    #[error("Something went wrong with encryption")]
    CryptoError,
    #[error("Database not initialized. Run `passvault init` first.")]
    DbNotInitializedError,
    #[error("Passvault already initialized. Run `passvault` to see options.")]
    DbAlreadyInitializedError,
    #[error(
        "Website not found. Please try again or run `passvault list` to see all stored websites."
    )]
    WebsiteNotFoundError,
    #[error("Wrong master password")]
    WrongMasterPasswordError,
    #[error("Something went wrong with clipboard operations")]
    ClipboardError,
    #[error("Failed to reset database")]
    ResetDbError,
    #[error(
        "A password with that website name already exists. Try a different variation if needed."
    )]
    WebsiteAlreadyExistsError,
    #[error("Failed to create export file")]
    ExportFileError,
}
