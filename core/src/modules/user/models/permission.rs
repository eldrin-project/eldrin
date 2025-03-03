use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::types::Uuid;

/// Represents a permission in the system
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct Permission {
    /// Unique permission identifier
    pub id: Uuid,
    
    /// Permission name
    pub name: String,
    
    /// Permission description
    pub description: Option<String>,
    
    /// The resource this permission applies to
    pub resource: String,
    
    /// The action this permission allows
    pub action: String,
    
    /// When the permission was created
    pub created_at: DateTime<Utc>,
    
    /// When the permission was last updated
    pub updated_at: DateTime<Utc>,
}