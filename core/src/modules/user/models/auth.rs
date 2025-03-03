use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::types::Uuid;

/// User roles in the system (legacy enum, maintained for backward compatibility)
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum UserRole {
    Admin,
    User,
    Guest,
}

/// Authentication methods supported by the system
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum AuthMethod {
    EmailPassword,
    MagicLink,
    SmsCode,
    Github,
    Google,
    Keycloak,
}

/// Represents a user's connection to an external authentication provider
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExternalAuth {
    /// Reference to the user
    pub user_id: Uuid,
    
    /// The provider (github, google, etc.)
    pub provider: String,
    
    /// External provider's user ID
    pub provider_user_id: String,
    
    /// Access token (encrypted)
    pub access_token: Option<String>,
    
    /// Refresh token (encrypted)
    pub refresh_token: Option<String>,
    
    /// When the token expires
    pub expires_at: Option<DateTime<Utc>>,
    
    /// Additional provider-specific data
    pub provider_data: Option<serde_json::Value>,
}