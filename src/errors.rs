use thiserror::Error;

#[derive(Error, Debug)]
pub enum PassmanError {
    #[error("Authentication error")]
    AuthError,
}
