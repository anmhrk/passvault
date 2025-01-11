use argon2::password_hash::SaltString;
use chrono::{DateTime, Duration, Utc};

use crate::errors::PassmanError;

pub fn now() -> String {
    let now: DateTime<Utc> = Utc::now();
    now.to_rfc3339()
}

pub fn get_salt_string(salt: &str) -> Result<SaltString, PassmanError> {
    SaltString::from_b64(salt).map_err(|_| PassmanError::SaltStringError)
}

pub fn is_session_expired(last_access: &str) -> bool {
    // keeps session alive for 5 minutes, then will require master password
    // add lock command later to kill session instantly

    let timeout = Duration::minutes(5);
    let last_access: DateTime<Utc> = last_access.parse().unwrap();
    Utc::now() - last_access > timeout
}
