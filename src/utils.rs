use anyhow::Result;
use std::io::{ self, Write };
use rpassword::read_password;

pub fn prompt_password(prompt: &str) -> Result<String> {
    print!("{}: ", prompt);
    io::stdout().flush()?;
    let password = read_password()?;
    Ok(password)
}

pub fn prompt_input(prompt: &str) -> Result<String> {
    print!("{}: ", prompt);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}
