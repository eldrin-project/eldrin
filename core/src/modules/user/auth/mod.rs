mod password;
mod token;
pub mod oauth;
mod magic_link;
mod sms;

pub use password::PasswordManager;
pub use token::{TokenManager, TokenType, TokenClaims};
pub use oauth::{OAuthManager, OAuthProvider};
pub use magic_link::MagicLinkManager;
pub use sms::SmsManager;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,
    
    #[error("Token expired")]
    TokenExpired,
    
    #[error("Invalid token")]
    InvalidToken,
    
    #[error("User not found")]
    UserNotFound,
    
    #[error("Provider error: {0}")]
    ProviderError(String),
    
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    
    #[error("Storage error: {0}")]
    StorageError(String),
    
    #[error("Request error: {0}")]
    RequestError(#[from] reqwest::Error),
    
    #[error("JWT error: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),
    
    #[error("Unauthorized")]
    Unauthorized,
    
    #[error("Internal error: {0}")]
    InternalError(String),
}