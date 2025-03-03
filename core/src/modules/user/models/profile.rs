use serde::{Deserialize, Serialize};
use sqlx::types::Uuid;
use std::collections::HashMap;

/// User profile information
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserProfile {
    /// Reference to the user
    pub user_id: Uuid,
    
    /// User's display name
    pub display_name: Option<String>,
    
    /// User's avatar URL
    pub avatar_url: Option<String>,
    
    /// User's preferred locale
    pub locale: Option<String>,
    
    /// User's timezone
    pub timezone: Option<String>,
    
    /// Additional profile data as JSON
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}