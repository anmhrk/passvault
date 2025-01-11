use argon2::{Argon2, PasswordHash, PasswordVerifier};

pub struct Crypto {
    argon2: Argon2<'static>,
}

impl Crypto {
    pub fn new() -> Self {
        Crypto { argon2: Argon2::default() }
    }
}
